package eu.h2020.symbiote.client.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;

import eu.h2020.symbiote.cloud.model.data.observation.Observation;
import eu.h2020.symbiote.core.internal.ResourceUrlsResponse;
import eu.h2020.symbiote.security.ClientSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ISecurityHandler;

import eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * @author Vasileios Glykantzis (ICOM)
 * @since 9/17/2017.
 */
@RestController
public class Controller {

    private static Log log = LogFactory.getLog(Controller.class);

    private String symbIoTeCoreUrl;
    private RestTemplate restTemplate;
    private ISecurityHandler securityHandler;
    private String username;
    private String password;
    private String clientId;

    @Autowired
    public Controller(@Qualifier("symbIoTeCoreUrl") String symbIoTeCoreUrl, RestTemplate restTemplate,
                      @Value("${coreAAMAddress}") String coreAAMAddress, @Value("${keystorePath}") String keystorePath,
                      @Value("${keystorePassword}") String keystorePassword, @Value("${userId}") String userId,
                      @Value("${demoApp.username}") String username, @Value("${demoApp.password}") String password,
                      @Value("${clientId}") String clientId)
            throws SecurityHandlerException {

        Assert.notNull(symbIoTeCoreUrl,"symbIoTeCoreUrl can not be null!");
        this.symbIoTeCoreUrl = symbIoTeCoreUrl;

        Assert.notNull(restTemplate,"RestTemplate can not be null!");
        this.restTemplate = restTemplate;

        Assert.notNull(coreAAMAddress,"coreAAMAddress can not be null!");
        Assert.notNull(keystorePath,"keystorePath can not be null!");
        Assert.notNull(keystorePassword,"keystorePassword can not be null!");
        Assert.notNull(userId,"userId can not be null!");

        Assert.notNull(username,"username can not be null!");
        this.username = username;

        Assert.notNull(password,"password can not be null!");
        this.password = password;

        Assert.notNull(clientId,"clientId can not be null!");
        this.clientId = clientId;

        log.info(symbIoTeCoreUrl);
        log.info(coreAAMAddress);
        log.info(keystorePath);
        log.info(keystorePassword);
        log.info(userId);
        log.info(username);
        log.info(password);
        log.info(clientId);

        securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(coreAAMAddress, keystorePath,
                keystorePassword, userId);

    }

    @CrossOrigin
    @PostMapping("/get_resource_url")
    public ResponseEntity<?> getResourceUrlFromCram(@RequestParam String resourceId) {

        log.info("Requesting url from CRAM for the resource with id: " + resourceId);

        String cramRequestUrl = symbIoTeCoreUrl + "/resourceUrls?id=" + resourceId;
        return sendGETRequestAndVerifyResponse(cramRequestUrl, SecurityConstants.CORE_AAM_INSTANCE_ID, "cram",
                new ParameterizedTypeReference<ResourceUrlsResponse>() {});

    }

    @CrossOrigin
    @PostMapping("/observations")
    public ResponseEntity<?> getResourceObservationHistory(@RequestParam String resourceUrl,
                                                           @RequestParam String platformId) {

        log.info("Getting observations for the resource with url: " + resourceUrl);

        return sendGETRequestAndVerifyResponse(resourceUrl, platformId, "rap",
                new ParameterizedTypeReference<List<Observation>>() {});
    }

    private ResponseEntity<?> sendGETRequestAndVerifyResponse(String url, String platformId, String componentId,
                                                              ParameterizedTypeReference responseTypeRef) {

        Map<String, String> securityRequestHeaders;
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        // Insert Security Request into the headers
        try {

            Set<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();
            securityHandler.getCertificate(availableAAMs.get(platformId), username, password, clientId);
            Token homeToken = securityHandler.login(availableAAMs.get(platformId));

            HomeCredentials homeCredentials = securityHandler.getAcquiredCredentials().get(platformId).homeCredentials;
            authorizationCredentialsSet.add(new AuthorizationCredentials(homeToken, homeCredentials.homeAAM, homeCredentials));

            SecurityRequest securityRequest = MutualAuthenticationHelper.getSecurityRequest(authorizationCredentialsSet, false);
            securityRequestHeaders = securityRequest.getSecurityRequestHeaderParams();

        } catch (SecurityHandlerException | ValidationException | JsonProcessingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new ResponseEntity<>(e.getMessage(), new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
        }


        for (Map.Entry<String, String> entry : securityRequestHeaders.entrySet()) {
            httpHeaders.add(entry.getKey(), entry.getValue());
        }

        HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);

        ResponseEntity<?> responseEntity = restTemplate.exchange(url, HttpMethod.GET, httpEntity, responseTypeRef);

        log.info("response = " + responseEntity);
        log.info("headers = " + responseEntity.getHeaders());
        log.info("body = " + responseEntity.getBody());

        String serviceResponse = responseEntity.getHeaders().get(SecurityConstants.SECURITY_RESPONSE_HEADER).get(0);

        if (serviceResponse == null)
            return new ResponseEntity<>("The receiver was not authenticated", new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);


        boolean isServiceResponseVerified;
        try {
            isServiceResponseVerified = MutualAuthenticationHelper.isServiceResponseVerified(
                    serviceResponse, securityHandler.getComponentCertificate(componentId, platformId));
        } catch (CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new ResponseEntity<>(e.getMessage(), new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        if (isServiceResponseVerified) {
            return new ResponseEntity<>(responseEntity.getBody(), new HttpHeaders(), responseEntity.getStatusCode());
        } else {
            return new ResponseEntity<>("The service response is not verified", new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}
