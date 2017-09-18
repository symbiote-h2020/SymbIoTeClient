package eu.h2020.symbiote.client.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;

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

    @Autowired
    public Controller(@Qualifier("symbIoTeCoreUrl") String symbIoTeCoreUrl, RestTemplate restTemplate,
                      @Value("coreAAMAdress") String coreAAMAddress, @Value("keystorePath") String keystorePath,
                      @Value("keystorePassword") String keystorePassword, @Value("userId") String userId)
            throws SecurityHandlerException {

        Assert.notNull(symbIoTeCoreUrl,"symbIoTeCoreUrl can not be null!");
        this.symbIoTeCoreUrl = symbIoTeCoreUrl;

        Assert.notNull(restTemplate,"RestTemplate can not be null!");
        this.restTemplate = restTemplate;

        Assert.notNull(coreAAMAddress,"coreAAMAddress can not be null!");
        Assert.notNull(keystorePath,"keystorePath can not be null!");
        Assert.notNull(keystorePassword,"keystorePassword can not be null!");
        Assert.notNull(userId,"userId can not be null!");

        securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(coreAAMAddress, keystorePath,
                keystorePassword, userId);

    }

    @PostMapping("/get_resource_url")
    public ResponseEntity<?> getResourceUrlFromCram(@RequestParam String resourceId) {

        log.info("Requesting url from CRAM for the resource with id: " + resourceId);

        String cramRequestUrl = symbIoTeCoreUrl + "/resourceUrls?id=" + resourceId;
        return sendGETRequestAndVerifyResponse(cramRequestUrl, SecurityConstants.CORE_AAM_INSTANCE_ID);
    }

    @PostMapping("/observations")
    public ResponseEntity<?> getResourceObservationHistory(@RequestParam String resourceUrl,
                                                           @RequestParam String platformId) {

        log.info("Getting observations for the resource with id: " + resourceUrl);

        return sendGETRequestAndVerifyResponse(resourceUrl, platformId);
    }

    private ResponseEntity<?> sendGETRequestAndVerifyResponse(String url, String aamId) {
        Map<String, String> securityRequestHeaders;
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        // Insert Security Request in to the headers
        try {

            Set<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();
            Token homeToken = securityHandler.login(availableAAMs.get(aamId));

            HomeCredentials homeCredentials = securityHandler.getAcquiredCredentials().get(aamId).homeCredentials;
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

        ParameterizedTypeReference<Map<String, String>> typeRef = new ParameterizedTypeReference<Map<String, String>>() {};
        ResponseEntity<?> responseEntity = restTemplate.exchange(url, HttpMethod.GET, httpEntity, typeRef);

        String serviceResponse = responseEntity.getHeaders().get(SecurityConstants.SECURITY_RESPONSE_HEADER).get(0);

        if (serviceResponse == null)
            return new ResponseEntity<>("Service Response not present", new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);


        boolean isServiceResponseVerified;
        try {
            isServiceResponseVerified = MutualAuthenticationHelper.isServiceResponseVerified(
                    serviceResponse, securityHandler.getAcquiredCredentials().get(aamId).homeCredentials.certificate);
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
