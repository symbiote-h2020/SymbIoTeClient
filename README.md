[![Build Status](https://api.travis-ci.org/symbiote-h2020/SymbIoTeClient.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/SymbIoTeClient)
[![codecov.io](https://codecov.io/github/symbiote-h2020/SymbIoTeClient/branch/master/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/SymbIoTeClient/branch/develop)

# SymbIoTeClient
This is a backend client which listens by default at port 8777 and uses the security handler to interact with core and platform components. It supports 3
operations as of now:
* Register a user in the platform AAM by using the paamOwner credentials. For this operation, you have to submit a
POST request to *"/register_to_PAAM"* with request parameters:
```
platformId=yourPlatformId
```
* Get the resource url from core (i.e CRAM) by submitting a POST to *"/get_resource_url"* with request parameters:
```
resourceId=the_resourceID
```
As a result, you get a url with the following format:
```
https://{platform_interworking_interface_url}/rap/Sensors('resourceId')
```
* Get observations using the resource url. The resource url you get by the previous operation is the generic url. So, you have to append the OData operator e.g. "/Observation". Then, to access the resource you have to submit a POST url to *"/observations"* with the following request parameters:
```
resourceUrl=https://{platform_interworking_interface_url}/rap/Sensors('resourceId')&platformId=yourPlatformId
```

# Some Remarks
* The configuration of the SymbIoTeClient is done in the src/main/resources/application.properties file
* The paamOwner credentials are needed only for user registration in the local platforms AAMs. The webApp credentials are actually the credentials of the the user (i.e. webApp). Please, for simplification use the same user credentials both in Core and in PAAM. So, if you have an account in the core with icom/icom, use the same credentials for the platform user (i.e. webApp). The paamOwner credentials can be different
* The SymbIoTeClient uses the symbIoTe core for finding the AAMs and symbIoTe core assumes that nginx is running. So, you will need your nginx running to have resolvable paths, with a slightly new configuration. Comment all the paam configuration in your nginx (i.e. all your paths which start with /paam/ in the nginx configuration) and add the following:
```
        location /paam/ {
  
          proxy_set_header        Host $host;
          proxy_set_header        X-Real-IP $remote_addr;
          proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
          proxy_set_header        X-Forwarded-Proto $scheme;
  
          proxy_pass http://localhost:{aam port}/; ## NOTE: This should match the PAAM port in the CloudConfigProperties
        }
```
You have to put there the port that your PAAM listens to. Slashes are important here, so make sure that you do not miss anyone.
