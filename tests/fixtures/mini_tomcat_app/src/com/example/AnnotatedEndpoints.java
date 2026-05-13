package com.example;

@WebServlet(value={"/servlet/report", "/servlet/export"})
class ReportServlet {}

@Path("/api")
class ReportResource {
    @GET
    @Path("/reports")
    public String listReports() { return "ok"; }

    @POST
    @Path("/reports")
    public String createReport() { return "ok"; }
}

@WebService
class AuditSoapService {
    @WebMethod
    public void syncAudit() {}
}
