package main

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/knqyf263/kube-trivy/pkg/integration/slack"
	"github.com/knqyf263/kube-trivy/pkg/trivy"
	"golang.org/x/xerrors"
	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	informers "k8s.io/client-go/informers/apps/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	listers "k8s.io/client-go/listers/apps/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type Controller struct {
	clientset         kubernetes.Interface
	deploymentsLister listers.DeploymentLister
	daemonsetsLister  listers.DaemonSetLister
	deploymentsSynced cache.InformerSynced
	workqueue         workqueue.RateLimitingInterface
}

func NewController(clientset kubernetes.Interface, deploymentInformer informers.DeploymentInformer, daemonsetInformer informers.DaemonSetInformer) *Controller {

	utilruntime.Must(scheme.AddToScheme(scheme.Scheme))
	controller := &Controller{
		clientset:         clientset,
		deploymentsLister: deploymentInformer.Lister(),
		daemonsetsLister:  daemonsetInformer.Lister(),
		deploymentsSynced: deploymentInformer.Informer().HasSynced,
		workqueue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Trivy"),
	}
	deploymentInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*appsv1.Deployment)
			oldDepl := old.(*appsv1.Deployment)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				return
			}
			if newDepl.ObjectMeta.Generation == oldDepl.ObjectMeta.Generation {
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.handleObject,
	})

	daemonsetInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newDepl := new.(*appsv1.DaemonSet)
			oldDepl := old.(*appsv1.DaemonSet)
			if newDepl.ResourceVersion == oldDepl.ResourceVersion {
				return
			}
			if newDepl.ObjectMeta.Generation == oldDepl.ObjectMeta.Generation {
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.handleObject,
	})
	return controller
}

func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer utilruntime.HandleCrash()
	defer c.workqueue.ShutDown()

	if ok := cache.WaitForCacheSync(stopCh, c.deploymentsSynced); !ok {
		return xerrors.New("failed to wait for caches to sync")
	}

	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
	return nil
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
	}
	c.enqueue(object)
}

func MetaNamespaceKeyFunc(obj interface{}) (string, error) {
	key, err := cache.MetaNamespaceKeyFunc(obj)
	if err != nil {
		return "", xerrors.Errorf("failed to MetaNamespaceKeyFunc: %v", err)
	}
	return getType(obj)[1:] + "/" + key, nil
}

func getType(obj interface{}) string {
	if t := reflect.TypeOf(obj); t.Kind() == reflect.Ptr {
		return "*" + t.Elem().Name()
	} else {
		return t.Name()
	}
}

func SplitMetaNamespaceKey(key string) (kind, namespace, name string) {
	parts := strings.Split(key, "/")

	return parts[0], parts[1], parts[2]
}

func (c *Controller) enqueue(obj interface{}) {
	var key string
	var err error
	if key, err = MetaNamespaceKeyFunc(obj); err != nil {
		utilruntime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

func (c *Controller) processNextWorkItem() bool {
	obj, shutdown := c.workqueue.Get()

	if shutdown {
		return false
	}

	err := func(obj interface{}) error {
		defer c.workqueue.Done(obj)

		var key string
		var ok bool
		if key, ok = obj.(string); !ok {
			c.workqueue.Forget(obj)
			utilruntime.HandleError(fmt.Errorf("expected string in workqueue but got %#v", obj))
			return nil
		}

		if err := c.syncHandler(key); err != nil {
			c.workqueue.AddRateLimited(key)
			return xerrors.Errorf("failed to error syncing: %s", err)
		}

		c.workqueue.Forget(obj)
		return nil
	}(obj)

	if err != nil {
		utilruntime.HandleError(err)
		return true
	}

	return true
}

func (c *Controller) syncHandler(key string) error {
	s := slack.SlackWriter{}
	kind, namespace, name := SplitMetaNamespaceKey(key)

	switch kind {
	case "DaemonSet":
		daemonset, err := c.daemonsetsLister.DaemonSets(namespace).Get(name)
		if err != nil {
			if errors.IsNotFound(err) {
				utilruntime.HandleError(fmt.Errorf("daemonset '%s' in work queue no longer exists", key))
				return nil
			}

			return err
		}
		s.NotificationResource(kind, name, namespace)
		for _, c := range daemonset.Spec.Template.Spec.Containers {
			results, err := trivy.ScanImage(c.Image)
			if err != nil {
				return xerrors.Errorf("failed to scanImage: %w", err)
			}
			err = trivy.SaveScanResult(key, *results)
			if err != nil {
				return xerrors.Errorf("failed to save scanResult: %w", err)
			}
			*results, err = trivy.CompareResults(key, *results)
			if err != nil {
				return xerrors.Errorf("failed to compare scanResult: %w", err)
			}
			s.NotificationAddOrModifyContainer(*results)
		}

	case "Deployment":
		deployment, err := c.deploymentsLister.Deployments(namespace).Get(name)
		if err != nil {
			if errors.IsNotFound(err) {
				utilruntime.HandleError(fmt.Errorf("deployment '%s' in work queue no longer exists", key))
				return nil
			}

			return err
		}
		s.NotificationResource(kind, name, namespace)
		for _, c := range deployment.Spec.Template.Spec.Containers {
			results, err := trivy.ScanImage(c.Image)
			if err != nil {
				return xerrors.Errorf("failed to scanImage: %w", err)
			}
			err = trivy.SaveScanResult(key, *results)
			if err != nil {
				return xerrors.Errorf("failed to save scanResult: %w", err)
			}
			*results, err = trivy.CompareResults(key, *results)
			if err != nil {
				return xerrors.Errorf("failed to compare scanResult: %w", err)
			}
			s.NotificationAddOrModifyContainer(*results)
		}

	}
	return nil
}
