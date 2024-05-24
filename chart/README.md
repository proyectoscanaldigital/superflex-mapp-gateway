# superflex-api-gateway Chart

This is the chart for the [superflex-api-gateway](https://bitbucket.org/glicsolutions/superflex-api-gateway.git).

## Installation

When installing this app you'll have to change some values in values.yaml.

----

1. The variable replicaCount defines how many instances of this microservice will execute
```yaml
replicaCount: 2
```
2. The variable serviceName is used to define the name of the service, sometimes can be different to the repo name or image name, like this case.
```yaml
serviceName: "my-serviceName"
```
3. Database data
```yaml
db:
  enabled: true
  hosts: 
    - db-host:port
  name: "my-databse"
  ssl: required
```
4. Consul data
```yaml
consul:
  enabled: true
  host: "consul-serviceName.namespace.svc"
  port: "8500"
```
5. Vault data
```yaml
vault:
  enabled: true
  host: "vault.common.svc"
  port: "8200"
  roleid: "7098702e-1111-1111-1111-186410f5a88e"
  secretid: "4a7c17dc-1111-1111-1111-636df7448538"
```
6. Pick the app and version by changing the value repository and tag
```yaml
repository: harbor.eks.glic-solutions.com/glic/superflex-api-gateway
  pullPolicy: Always
  # Overrides the image tag whose default is the chart appVersion.
  tag: "latest"
```
7. To pull the image is needed to use imagePullSecrets, for STG there is a pre-loaded secret called harbor-registry, this secret will have the Harbor credentials
```yaml
imagePullSecrets:
  - name: registry-secret
nameOverride: ""
fullnameOverride: ""
```
8. The app port will be used as where the app is listening and hazelcast for this same service.
```yaml
ports:
  - name: app
    containerPort: 9003
    protocol: TCP
  - name: hazelcast
    containerPort: 5701
    protocol: TCP
```
9. Environment variables, in this example is enable production profile and showconsole to send logs to stdout
```yaml
env:
  - name: SPRING_PROFILES_ACTIVE
    value: "k8s,production"
  - name: SPRING_CONFIG_LOCATION
    value: "classpath:/,file:conf/"
  - name: POD_IP
    valueFrom:
      fieldRef:
        fieldPath: status.podIP
```
10. Service port will be the port in which the Kubernetes service will listen, this port is also used for Liveness and Readiness Probes
```yaml
service:
  type: ClusterIP
  port: 9003
  
```
11. NodePort will be the port in which the Kubernetes service will be exposed, this port should be between 30000-32767
```yaml
nodePort:
  enabled: true
  port: 30081
```
12. Designated resources for this app. Check the reference [here](https://glic-solutions.atlassian.net/wiki/spaces/PAYM/pages/1149435914/Gateway+Minimal+Test+Environment+Requirements+for+K8s).
```yaml
resources: 
  limits:
    cpu: 250m
    memory: 2048Mi
  requests:
    cpu: 100m
    memory: 1024Mi
```
13. ELK data
```yaml
rancherLogging:
  enabled: false
  namespace: "default"
  elk:
    host: "elk-serviceName.namespace.svc"
    port: "9200"
    user: "admin"
    secret: "password"