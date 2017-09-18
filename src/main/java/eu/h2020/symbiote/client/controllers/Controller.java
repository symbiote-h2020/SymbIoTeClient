package eu.h2020.symbiote.client.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;

import eu.h2020.symbiote.cloud.model.data.observation.Observation;
import eu.h2020.symbiote.security.ClientSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.Certificate;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.payloads.AAM;
import eu.h2020.symbiote.security.communication.payloads.SecurityCredentials;
import eu.h2020.symbiote.security.communication.payloads.SecurityRequest;
import eu.h2020.symbiote.security.handler.ISecurityHandler;

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

import java.util.*;

import static eu.h2020.symbiote.security.helpers.MutualAuthenticationHelper.hashSHA256;

/**
 * @author Vasileios Glykantzis (ICOM)
 * @since 9/17/2017.
 */
@RestController
public class Controller {

    private static Log log = LogFactory.getLog(Controller.class);

    private String symbIoTeCoreUrl;
    private RestTemplate restTemplate;
    private String coreAAMAddress;
    private String keystorePath;
    private String keystorePassword;
    private String userId;
    private String username;
    private String password;
    private String clientId;
    private ISecurityHandler securityHandler;

    @Autowired
    public Controller(@Qualifier("symbIoTeCoreUrl") String symbIoTeCoreUrl, RestTemplate restTemplate,
                      @Value("coreAAMAdress") String coreAAMAddress, @Value("keystorePath") String keystorePath,
                      @Value("keystorePassword") String keystorePassword, @Value("userId") String userId,
                      @Value("username") String username, @Value("password") String password,
                      @Value("clientId") String clientId)
            throws SecurityHandlerException {

        Assert.notNull(symbIoTeCoreUrl,"symbIoTeCoreUrl can not be null!");
        this.symbIoTeCoreUrl = symbIoTeCoreUrl;

        Assert.notNull(restTemplate,"RestTemplate can not be null!");
        this.restTemplate = restTemplate;

        Assert.notNull(coreAAMAddress,"coreAAMAddress can not be null!");
        this.coreAAMAddress = coreAAMAddress;

        Assert.notNull(keystorePath,"keystorePath can not be null!");
        this.keystorePath = keystorePath;

        Assert.notNull(keystorePassword,"keystorePassword can not be null!");
        this.keystorePassword = keystorePassword;

        Assert.notNull(userId,"userId can not be null!");
        this.userId = userId;

        Assert.notNull(username,"username can not be null!");
        this.username = username;

        Assert.notNull(password,"password can not be null!");
        this.password = password;

        Assert.notNull(clientId,"clientId can not be null!");
        this.clientId = clientId;

        securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(coreAAMAddress, keystorePath,
                keystorePassword, userId);

    }

    @PostMapping("/get_resource_url")
    public ResponseEntity<?> getResourceUrlFromCram(@RequestParam String resourceId) {

        log.info("Requesting url from CRAM for the resource with id: " + resourceId);

        String cramRequestUrl = symbIoTeCoreUrl + "/resourceUrls?id=" + resourceId;
        Map<String, String> securityRequestHeaders = new HashMap<>();
        HttpHeaders cramHttpHeaders = new HttpHeaders();
        cramHttpHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        cramHttpHeaders.setContentType(MediaType.APPLICATION_JSON);

        // Insert Security Request in to the headers
        try {
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();
            Token coreToken = securityHandler.login(availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID));
            Certificate coreCertificate = securityHandler.getCertificate(availableAAMs.get(SecurityConstants.CORE_AAM_INSTANCE_ID),
                    username, password, clientId);


            String authenticationChallenge = "";
            String clientCertificateString = "";
            String signingAAMCertificate = "";

            Set<SecurityCredentials> securityCredentials = new HashSet<>();
            securityCredentials.add(new SecurityCredentials(
                    coreToken.getToken(), Optional.of(authenticationChallenge),
                    Optional.of(clientCertificateString), Optional.of(signingAAMCertificate),
                    Optional.empty()));

            Date timestamp = new Date();

            SecurityRequest coreSecurityRequest = new SecurityRequest(securityCredentials, timestamp.getTime());
            securityRequestHeaders = coreSecurityRequest.getSecurityRequestHeaderParams();

        } catch (SecurityHandlerException e) {
            e.printStackTrace();
        } catch (ValidationException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        for (Map.Entry<String, String> entry : securityRequestHeaders.entrySet()) {
            cramHttpHeaders.add(entry.getKey(), entry.getValue());
        }

        HttpEntity<String> cramEntity = new HttpEntity<>(cramHttpHeaders);

        ParameterizedTypeReference<Map<String, String>> typeRef = new ParameterizedTypeReference<Map<String, String>>() {};
        ResponseEntity<Map<String, String>> cramResponseEntity = restTemplate.exchange(
                cramRequestUrl, HttpMethod.GET, cramEntity, typeRef);

        if (cramResponseEntity.getStatusCode() == HttpStatus.OK) {
            log.info("The request was successful");
            return new ResponseEntity<>(cramResponseEntity.getBody(), new HttpHeaders(), HttpStatus.OK);
        } else {
            log.info("The request failed: " + cramResponseEntity.getBody());
            return new ResponseEntity<>(cramResponseEntity.getBody(), new HttpHeaders(), cramResponseEntity.getStatusCode());
        }
    }

    @PostMapping("/observations")
    public ResponseEntity<?> getResourceObservationHistory(@RequestParam String resourceUrl,
                                                           @RequestParam String platformId) {

        log.info("Getting observations for the resource with id: " + resourceUrl);

        Map<String, String> securityRequestHeaders = new HashMap<>();
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        // Insert Security Request in to the headers
        try {
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();
            Token coreToken = securityHandler.login(availableAAMs.get(platformId));
            Certificate coreCertificate = securityHandler.getCertificate(availableAAMs.get(platformId),
                    username, password, clientId);


            String authenticationChallenge = "";
            String clientCertificateString = "";
            String signingAAMCertificate = "";

            Set<SecurityCredentials> securityCredentials = new HashSet<>();
            securityCredentials.add(new SecurityCredentials(
                    coreToken.getToken(), Optional.of(authenticationChallenge),
                    Optional.of(clientCertificateString), Optional.of(signingAAMCertificate),
                    Optional.empty()));

            Date timestamp = new Date();

            SecurityRequest securityRequest = new SecurityRequest(securityCredentials, timestamp.getTime());
            securityRequestHeaders = securityRequest.getSecurityRequestHeaderParams();

        } catch (SecurityHandlerException e) {
            e.printStackTrace();
        } catch (ValidationException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        for (Map.Entry<String, String> entry : securityRequestHeaders.entrySet()) {
            httpHeaders.add(entry.getKey(), entry.getValue());
        }

        HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);

        ParameterizedTypeReference<List<Observation>> typeRef = new ParameterizedTypeReference<List<Observation>>() {};
        ResponseEntity<List<Observation>> cramResponseEntity = restTemplate.exchange(
                resourceUrl, HttpMethod.GET, httpEntity, typeRef);

        if (cramResponseEntity.getStatusCode() == HttpStatus.OK) {
            log.info("The request was successful");
            return new ResponseEntity<>(cramResponseEntity.getBody(), new HttpHeaders(), HttpStatus.OK);
        } else {
            log.info("The request failed: " + cramResponseEntity.getBody());
            return new ResponseEntity<>(cramResponseEntity.getBody(), new HttpHeaders(), cramResponseEntity.getStatusCode());
        }
    }
}
