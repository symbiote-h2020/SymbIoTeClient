[![Build Status](https://api.travis-ci.org/symbiote-h2020/SymbIoTeClient.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/SymbIoTeClient)
[![codecov.io](https://codecov.io/github/symbiote-h2020/SymbIoTeClient/branch/master/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/SymbIoTeClient/branch/develop)

# SymbIoTeClient
This is a backend client which listens by default at port 8777 and uses the security handler to interact with core and 
platform components. It supports the following operations as of now:
* Register a user in the platform AAM by using the paamOwner credentials. For this operation, you have to submit a
POST request to *"/register_to_PAAM"* with request parameters:
```
platformId={yourPlatformId}&directAAMUrl={the_directurl_of_your_PAAM_not_through_nginx}
```

* Search for resources using the parameterized search query. For this operation, 
you have to submit a GET request to *"/query"* with the appropriate optional query 
parameters along with the following necessary parameter:
```
homePlatformId={the_platformId_from_which_you_request_a_token}
```

* Search for resources using a SPARQL query. For this operation, 
you have to submit a POST request to *"/sparqlQuery"* with the following body:
```
{
  "sparqlQueryRequest": {
    "sparqlQuery": "sparqlQuery string",
    "outputFormat": "SparqlQueryOutputFormat"
  },
  "homePlatformId": "The platform from which you get the token"
}
```

* Get the resource url from core (i.e CRAM) by submitting a POST to *"/get_resource_url"* 
with request parameters:
```
resourceId={the_resourceID}&platformId={the_platformId_from_which_you_request_a_token}
```
As a result, you get a url with the following format:
```
https://{platform_interworking_interface_url}/rap/Sensors('resourceId')
```
* Get observations by getting a home token and using the resource url. You have to POST
 to *"/observations"* or *"/observations_with_home_token"*. The resource url you get by the previous 
operation is the generic url. So, you have to append the OData operator e.g. "/Observations". Then, to access the resource you have to submit a POST url to *"/observations"* with the following request parameters:
```
resourceUrl={https://{platform_interworking_interface_url}/rap/Sensors('resourceId')}&platformId={yourPlatformId}
```

* Set parameters by getting a home token and using the resource url. You have to POST
 to *"/set"*. The resource url you get by the previous 
operation is the generic url. So, you have to append the OData operator. Then, to access the resource you have to submit 
a POST url to *"/observations"* which has as a body the input message and the following 
request parameters:
```
resourceUrl={https://{platform_interworking_interface_url}/rap/Sensors('resourceId')}&platformId={yourPlatformId}
```

* Get observations by getting a foreign token and using the resource url. You have to POST
 to *"/observations"* or *"/observations_with_home_token"*. The resource url you get by the previous 
operation is the generic url. So, you have to append the OData operator e.g. "/Observations". Then, to access the resource you have to submit a POST url to *"/observations"* with the following request parameters:
```
resourceUrl={https://{platform_interworking_interface_url}/rap/Sensors('resourceId')}&homePlatformId={the_platformId_from_which_you_request_a_token}&federatedPlatformId={the_platform_owing_the_resource}
```

# Some Remarks
* The configuration of the SymbIoTeClient is done in the src/main/resources/application.properties file
* The paamOwner credentials are needed only for user registration in the local platform
  AAMs. The webApp credentials are actually the credentials of the the user (i.e. webApp).
  Please, for simplification use the same user credentials both in Core and in PAAM.
  So, if you have an account in the core with icom/icom, use the same credentials for
  the platform user (i.e. webApp). The paamOwner credentials can be different
