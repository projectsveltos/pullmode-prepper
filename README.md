This is used when running pullmode sanity.
This Job is deployed in the management cluster and creates a ServiceAccount for sveltos-applier
with proper permissions.
Then it creates a Secret of type "kubernetes.io/service-account-token" associated to the
sveltos-applier ServiceAccount.
With this token it generates a Kubeconfig which is stored in a ConfigMap.

The Makefile takes the content of this ConfigMap and creates a Secret in the managed
cluster where sveltos-applier will be deployed. So that sveltos-applier can reach the
management and fetch the configuration it has to deploy.

None of the Makefile target should be directly invoked.

The main Makefile invokes those.