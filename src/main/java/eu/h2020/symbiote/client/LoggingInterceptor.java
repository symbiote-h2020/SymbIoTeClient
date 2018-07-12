//package eu.h2020.symbiote.client;
//
//import java.io.IOException;
//import java.io.UnsupportedEncodingException;
//import java.util.List;
//import java.util.Map.Entry;
//
//import org.apache.commons.io.IOUtils;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.http.HttpRequest;
//import org.springframework.http.client.ClientHttpRequestExecution;
//import org.springframework.http.client.ClientHttpRequestInterceptor;
//import org.springframework.http.client.ClientHttpResponse;
//import org.springframework.stereotype.Component;
//
//@Component
//public class LoggingInterceptor implements ClientHttpRequestInterceptor {
//    private static final Logger log = LoggerFactory.getLogger(LoggingInterceptor.class);
//
//    @Override
//    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
//            throws IOException {
//        traceRequest(request, body);
//        ClientHttpResponse response = execution.execute(request, body);
//        traceResponse(response);
//        return response;
//    }
//
//    private void traceRequest(HttpRequest request, byte[] body) {
//        log.debug("===========================request begin================================================");
//        log.debug("URI         : {}", request.getURI());
//        log.debug("Method      : {}", request.getMethod());
//        log.debug("*** Headers     : \n");
//        for(Entry<String, List<String>> entry: request.getHeaders().entrySet()) {
//           log.debug("{}: {}", entry.getKey(), entry.getValue());
//        }
//        try {
//            log.debug("*** Request body: {}", new String(body, "UTF-8"));
//        } catch (UnsupportedEncodingException e) {
//            log.error("Unsupported UTF-8", e);
//        }
//        log.debug("===========================request end================================================");
//    }
//
//    private void traceResponse(ClientHttpResponse response) {
//        log.debug("===========================response begin==========================================");
//        try {
//            log.debug("Status code  : {}", response.getStatusCode());
//            log.debug("Status text  : {}", response.getStatusText());
//            log.debug("*** Headers      : \n");
//            for(Entry<String, List<String>> entry: response.getHeaders().entrySet()) {
//                log.debug("{}: {}", entry.getKey(), entry.getValue());
//             }
//            log.debug("*** Response body: {}", IOUtils.toString(response.getBody()));
//        } catch (IOException e) {
//            log.error("Eror reading response.", e);
//        }
//        log.debug("===========================response end=================================================");
//    }
//}
