package eu.h2020.symbiote.client.model;

import eu.h2020.symbiote.core.ci.SparqlQueryRequest;

/**
 * @author Vasileios Glykantzis (ICOM)
 * @since 11/2/2017.
 */
public class SparqlQueryRequestWrapper {

    private SparqlQueryRequest sparqlQueryRequest;
    private String homePlatformId;

    public SparqlQueryRequestWrapper() {
    }

    public SparqlQueryRequestWrapper(SparqlQueryRequest sparqlQueryRequest, String homePlatformId) {
        this.sparqlQueryRequest = sparqlQueryRequest;
        this.homePlatformId = homePlatformId;
    }

    public SparqlQueryRequest getSparqlQueryRequest() {
        return sparqlQueryRequest;
    }

    public void setSparqlQueryRequest(SparqlQueryRequest sparqlQueryRequest) {
        this.sparqlQueryRequest = sparqlQueryRequest;
    }

    public String getHomePlatformId() {
        return homePlatformId;
    }

    public void setHomePlatformId(String homePlatformId) {
        this.homePlatformId = homePlatformId;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SparqlQueryRequestWrapper)) return false;

        SparqlQueryRequestWrapper that = (SparqlQueryRequestWrapper) o;

        if (getSparqlQueryRequest() != null ? !getSparqlQueryRequest().equals(that.getSparqlQueryRequest()) : that.getSparqlQueryRequest() != null)
            return false;
        return getHomePlatformId() != null ? getHomePlatformId().equals(that.getHomePlatformId()) : that.getHomePlatformId() == null;
    }

    @Override
    public int hashCode() {
        int result = getSparqlQueryRequest() != null ? getSparqlQueryRequest().hashCode() : 0;
        result = 31 * result + (getHomePlatformId() != null ? getHomePlatformId().hashCode() : 0);
        return result;
    }
}
