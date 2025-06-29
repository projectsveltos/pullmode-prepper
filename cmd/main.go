/*
Copyright 2025. projectsveltos.io. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"os"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apimachienruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/go-logr/logr"

	configv1beta1 "github.com/projectsveltos/addon-controller/api/v1beta1"
	libsveltosv1beta1 "github.com/projectsveltos/libsveltos/api/v1beta1"
	"github.com/projectsveltos/libsveltos/lib/k8s_utils"
)

var (
	setupLog = ctrl.Log.WithName("setup")
)

const (
	apiServer = " https://sveltos-management-control-plane:6443"
)

func main() {
	klog.InitFlags(nil)

	ctrl.SetLogger(klog.Background())

	scheme, err := initScheme()
	if err != nil {
		os.Exit(1)
	}

	restConfig := ctrl.GetConfigOrDie()

	var c client.Client
	c, err = client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		werr := fmt.Errorf("failed to connect: %w", err)
		log.Fatal(werr)
	}

	ctx := ctrl.SetupSignalHandler()
	err = createClusterResources(ctx, c, "default", "clusterapi-workload", ctrl.Log.WithName("prepare"))
	if err != nil {
		os.Exit(1)
	}
}

func initScheme() (*apimachienruntime.Scheme, error) {
	s := apimachienruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := libsveltosv1beta1.AddToScheme(s); err != nil {
		return nil, err
	}
	if err := configv1beta1.AddToScheme(s); err != nil {
		return nil, err
	}

	return s, nil
}

func createClusterResources(ctx context.Context, c client.Client,
	clusterNamespace, clusterName string, logger logr.Logger) error {

	err := createNamespace(ctx, c, clusterNamespace)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createNamespace failed: %s", err))
		return err
	}

	err = createServiceAccount(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createNamespace failed: %s", err))
		return err
	}

	err = createSecret(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createSecret failed: %s", err))
		return err
	}

	err = createRole(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createRole failed: %s", err))
		return err
	}

	err = createClusterRole(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createRole failed: %s", err))
		return err
	}

	err = createRoleBinding(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createRoleBinding failed: %s", err))
		return err
	}

	err = createClusterRoleBinding(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createClusterRoleBinding failed: %s", err))
		return err
	}

	err = createSveltosCluster(ctx, c, clusterNamespace, clusterName)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("createSveltosCluster failed: %s", err))
		return err
	}

	kubeconfig, err := getKubeconfig(ctx, c, clusterNamespace, clusterName, apiServer)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("getKubeconfig failed: %s", err))
		return err
	}

	err = storeKubeconfig(ctx, c, clusterNamespace, clusterName, kubeconfig)
	if err != nil {
		logger.V(0).Info(fmt.Sprintf("storeKubeconfig failed: %s", err))
		return err
	}

	return nil
}

func createNamespace(ctx context.Context, c client.Client, name string) error {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	err := c.Create(ctx, ns)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createServiceAccount(ctx context.Context, c client.Client, namespace, name string) error {
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
	}

	err := c.Create(ctx, serviceAccount)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createSecret(ctx context.Context, c client.Client, namespace, name string) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Annotations: map[string]string{
				corev1.ServiceAccountNameKey: name,
			},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}

	err := c.Create(ctx, secret)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createRole(ctx context.Context, c client.Client, namespace, name string) error {
	tmpl, err := template.New(name).Option("missingkey=error").Parse(role)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer,
		struct {
			Namespace, Name string
		}{
			Namespace: namespace,
			Name:      name,
		}); err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}
	instantiatedRole := buffer.String()

	uRole, err := k8s_utils.GetUnstructured([]byte(instantiatedRole))
	if err != nil {
		return err
	}

	err = c.Create(ctx, uRole)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createClusterRole(ctx context.Context, c client.Client, namespace, name string) error {
	tmpl, err := template.New(name).Option("missingkey=error").Parse(clusterRole)
	if err != nil {
		return err
	}

	var buffer bytes.Buffer

	if err := tmpl.Execute(&buffer,
		struct {
			Namespace, Name string
		}{
			Namespace: namespace,
			Name:      name,
		}); err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}
	instantiatedClusterRole := buffer.String()

	uClusterRole, err := k8s_utils.GetUnstructured([]byte(instantiatedClusterRole))
	if err != nil {
		return err
	}

	err = c.Create(ctx, uClusterRole)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createRoleBinding(ctx context.Context, c client.Client, namespace, name string) error {
	roleBinding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: namespace,
				Name:      name,
			},
		},
	}

	err := c.Create(ctx, roleBinding)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return nil
}

func createClusterRoleBinding(ctx context.Context, c client.Client, namespace, name string) error {
	// This binds serviceAccount with clusterRole. This grants read permissions for
	// resources like Classifier
	clusterRoleBinding := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace + "-" + name,
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     namespace + "-" + name,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Namespace: namespace,
				Name:      name,
			},
		},
	}

	err := c.Create(ctx, clusterRoleBinding)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func createSveltosCluster(ctx context.Context, c client.Client, namespace, name string) error {
	sveltosCluster := &libsveltosv1beta1.SveltosCluster{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"env":          "fv",
				"cluster-name": name,
			},
		},
		Spec: libsveltosv1beta1.SveltosClusterSpec{
			PullMode: true,
		},
	}

	err := c.Create(ctx, sveltosCluster)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
	}

	return err
}

func getKubeconfig(ctx context.Context, c client.Client,
	namespace, name, server string) (string, error) {

	secret := &corev1.Secret{}

	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, secret)
	if err != nil {
		return "", err
	}

	token, err := getToken(secret)
	if err != nil {
		return "", err
	}
	caCrt, err := getCaCrt(secret)
	if err != nil {
		return "", err
	}

	return getKubeconfigFromToken(server, token, caCrt), nil
}

func getToken(secret *corev1.Secret) ([]byte, error) {
	if secret.Data == nil {
		return nil, errors.New("secret data is nil")
	}

	token, ok := secret.Data["token"]
	if !ok {
		return nil, errors.New("secret data does not contain token key")
	}

	return token, nil
}

func getCaCrt(secret *corev1.Secret) ([]byte, error) {
	if secret.Data == nil {
		return nil, errors.New("secret data is nil")
	}

	caCrt, ok := secret.Data["ca.crt"]
	if !ok {
		return nil, errors.New("secret data does not contain ca.crt key")
	}

	return caCrt, nil
}

func getKubeconfigFromToken(server string, token, caData []byte) string {
	template := `apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: %s
    certificate-authority-data: %s
users:
- name: sveltos-applier
  user:
    token: %s
contexts:
- name: sveltos-context
  context:
    cluster: local
    user: sveltos-applier
current-context: sveltos-context`

	caDataBase64 := base64.StdEncoding.EncodeToString(caData)
	tokenString := string(token) // Token is already in the correct format

	data := fmt.Sprintf(template, server, caDataBase64, tokenString)

	return base64.StdEncoding.EncodeToString([]byte(data))
}

func storeKubeconfig(ctx context.Context, c client.Client,
	namespace, name, kubeconfig string) error {

	cm := &corev1.ConfigMap{}

	err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, cm)
	if err != nil {
		cm.ObjectMeta = metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		}
		cm.Data = map[string]string{
			"kubeconfig": kubeconfig,
		}
		return c.Create(ctx, cm)
	}

	cm.Data = map[string]string{
		"kubeconfig": kubeconfig,
	}
	return c.Update(ctx, cm)
}

var role = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
rules:
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - configurationgroups
  verbs:
  - get
  - list
  - watch
  - update
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - configurationgroups/status
  verbs:
  - get
  - update
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - configurationbundles
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - config.projectsveltos.io
  resources:
  - clusterconfigurations
  - clustersummaries
  verbs:
  - get
  - list
  - update
  - watch
- apiGroups:
  - config.projectsveltos.io
  resources:
  - clusterreports
  verbs:
  - create
  - delete
  - get
  - list
  - update
  - watch
- apiGroups:
  - config.projectsveltos.io
  resources:
  - clusterconfigurations/status
  - clusterreports/status
  - clustersummaries/status
  verbs:
  - get
  - list
  - update
  - patch
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - sveltosclusters
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - sveltosclusters/status
  verbs:
  - get
  - list
  - update
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - resourcesummaries
  verbs:
  - get
  - list
  - create
  - watch
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - resourcesummaries/status
  verbs:
  - get
  - update
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - classifiers
  verbs:
  - get
  - list
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - classifierreports
  verbs:
  - create
  - get
  - list
  - update
  - watch
`

var clusterRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ .Namespace }}-{{ .Name }}
rules:
- apiGroups:
  - lib.projectsveltos.io
  resources:
  - classifiers
  verbs:
  - get
  - list
  - watch
`
