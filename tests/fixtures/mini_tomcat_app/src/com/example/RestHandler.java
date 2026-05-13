package com.example;

class RestHandler {
    void handle(HttpServletRequest req) throws Exception {
        String body = req.getParameter("req");
        Runtime.getRuntime().exec(body);
        new ProcessBuilder(body).start();
        java.nio.file.Path path = java.nio.file.Paths.get(body);
        java.nio.file.Files.readAllBytes(path);
        java.nio.file.Files.write(path, body.getBytes());
        new java.io.FileInputStream(body);
        new java.io.FileOutputStream(body);
        new java.io.ObjectInputStream(stream).readObject();
        javax.xml.parsers.DocumentBuilderFactory.newInstance();
        java.util.Properties properties = new java.util.Properties();
        properties.load(stream);
        RelationalAPI.getInstance().executeQuery(query, connection);
        java.sql.DriverManager.getConnection(body);
        javax.naming.directory.InitialDirContext context = new javax.naming.directory.InitialDirContext();
        context.search("ldap://example", filter, controls);
    }
}
