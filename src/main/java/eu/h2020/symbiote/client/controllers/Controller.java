package eu.h2020.symbiote.client.controllers;

import com.fasterxml.jackson.core.JsonProcessingException;

import eu.h2020.symbiote.cloud.model.data.observation.Observation;
import eu.h2020.symbiote.core.internal.ResourceUrlsResponse;
import eu.h2020.symbiote.security.ClientSecurityHandlerFactory;
import eu.h2020.symbiote.security.commons.SecurityConstants;
import eu.h2020.symbiote.security.commons.Token;
import eu.h2020.symbiote.security.commons.credentials.AuthorizationCredentials;
import eu.h2020.symbiote.security.commons.credentials.HomeCredentials;
import eu.h2020.symbiote.security.commons.enums.ManagementStatus;
import eu.h2020.symbiote.security.commons.enums.OperationType;
import eu.h2020.symbiote.security.commons.enums.UserRole;
import eu.h2020.symbiote.security.commons.exceptions.custom.AAMException;
import eu.h2020.symbiote.security.commons.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.commons.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.communication.AAMClient;
import eu.h2020.symbiote.security.communication.IAAMClient;
import eu.h2020.symbiote.security.communication.payloads.*;
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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
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
    private String paamOwnerUsername;
    private String paamOwnerPassword;

    @Autowired
    public Controller(@Qualifier("symbIoTeCoreUrl") String symbIoTeCoreUrl, RestTemplate restTemplate,
                      @Value("${coreAAMAddress}") String coreAAMAddress, @Value("${keystorePath}") String keystorePath,
                      @Value("${keystorePassword}") String keystorePassword, @Value("${userId}") String userId,
                      @Value("${demoApp.username}") String username, @Value("${demoApp.password}") String password,
                      @Value("${clientId}") String clientId, @Value("${paamOwner.username}") String paamOwnerUsername,
                      @Value("${paamOwner.password}") String paamOwnerPassword)
            throws SecurityHandlerException, NoSuchAlgorithmException {

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

        Assert.notNull(paamOwnerUsername,"paamOwnerUsername can not be null!");
        this.paamOwnerUsername = paamOwnerUsername;

        Assert.notNull(paamOwnerPassword,"paamOwnerPassword can not be null!");
        this.paamOwnerPassword = paamOwnerPassword;

        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };
        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        try {
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        securityHandler = ClientSecurityHandlerFactory.getSecurityHandler(coreAAMAddress, keystorePath,
                keystorePassword, userId);

    }

    @CrossOrigin
    @PostMapping("/register_to_PAAM")
    public ResponseEntity<?> registerToPAAM(@RequestParam String platformId) {
        log.info("Registering to PAAM: " + platformId);
        try {
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();
            IAAMClient aamClient = new AAMClient(availableAAMs.get(platformId).getAamAddress());

            UserManagementRequest userManagementRequest = new UserManagementRequest(new
                    Credentials(paamOwnerUsername, paamOwnerPassword),
                    new Credentials(username, password),
                    new UserDetails(new Credentials(username, password), "", "icom@icom.com",
                            UserRole.USER, new HashMap<>(), new HashMap<>()),
                    OperationType.CREATE);

            try {
                aamClient.manageUser(userManagementRequest);
                log.info("User registration done");
            } catch (AAMException e) {
                log.error(e);
                return new ResponseEntity<>(e.getMessage(), new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } catch (SecurityHandlerException e) {
            e.printStackTrace();
            return new ResponseEntity<>(e.getMessage(), new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(ManagementStatus.OK, new HttpHeaders(), HttpStatus.OK);
    }

    @CrossOrigin
    @PostMapping("/get_resource_url")
    public ResponseEntity<?> getResourceUrlFromCram(@RequestParam String resourceId) {

        log.info("Requesting url from CRAM for the resource with id: " + resourceId);

        String cramRequestUrl = symbIoTeCoreUrl + "/resourceUrls?id=" + resourceId;
        return sendGETRequestAndVerifyResponse(cramRequestUrl, SecurityConstants.CORE_AAM_INSTANCE_ID, "cram");

    }

    @CrossOrigin
    @PostMapping("/observations")
    public ResponseEntity<?> getResourceObservationHistory(@RequestParam String resourceUrl,
                                                           @RequestParam String platformId) {

        log.info("Getting observations for the resource with url: " + resourceUrl);

        return sendGETRequestAndVerifyResponse(resourceUrl, platformId, "rap");
    }

    private ResponseEntity<?> sendGETRequestAndVerifyResponse(String url, String platformId, String componentId) {

        Map<String, String> securityRequestHeaders;
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.set("Accept", MediaType.APPLICATION_JSON_VALUE);
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);

        // Insert Security Request into the headers
        try {

            Set<AuthorizationCredentials> authorizationCredentialsSet = new HashSet<>();
            Map<String, AAM> availableAAMs = securityHandler.getAvailableAAMs();

            log.info("Getting certificate for " + availableAAMs.get(platformId).getAamInstanceId());
            securityHandler.getCertificate(availableAAMs.get(platformId), username, password, clientId);

            log.info("Getting token from " + availableAAMs.get(platformId).getAamInstanceId());
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
        log.info(httpHeaders);

        HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);

        ResponseEntity<?> responseEntity = restTemplate.exchange(url, HttpMethod.GET, httpEntity, Object.class);
//        ResponseEntity<?> responseEntity = restTemplate.exchange("https://symbiote.tel.fer.hr/rap/Sensor/59c374a037f6de49cc1be554/history",
//                HttpMethod.GET, httpEntity, Object.class);

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
