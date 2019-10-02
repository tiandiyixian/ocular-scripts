/* taint_tags.sc
 *
 * Version: 0.0.1
 * Ocular Version: 0.3.34
 * Author: Chetan Conikee <chetan@shiftLeft.io>
 * Execution-mode : Internal
 * Input: Application CPG
 * Output: JSON
 * 
 * Description: 
 * A categorized list of common SOURCES, INITIALIZERS, SANITIZERS, SINKS
 */

// SOURCES
val sources = Map(
    "HTTP" -> ".*HttpServletRequest.*|.*javax.servlet.http.HttpServletRequest.(getAuthType|getHeader|getHeaders|getMethod|getPathInfo|getPathTranslated|getContextPath|getQueryString|getRemoteUser|getRequestedSessionId|getRequestURI|getRequestURL|getServletPath|getAttribute|getAttributeNames|getCharacterEncoding|getContentType|getParameter|getParameterNames|getParameterValues|getParameterMap|getProtocol|getScheme|getServerName|getRemoteAddr|getRemoteHost|getLocalName|getLocalAddr|getReader).*",
    "SERVLET" -> ".*javax.servlet.ServletRequest.(getAttribute|getAttributeNames|getCharacterEncoding|getContentType|getParameter|getParameterNames|getParameterValues|getParameterMap|getProtocol|getScheme|getServerName|getRemoteAddr|getRemoteHost|getLocalName|getLocalAddr|getReader).*",
    "SERVLET_CONTEXT" -> ".*javax.servlet.ServletContext.(getResourceAsStream|getRealPath|getHeaderNames).*",
    "GENERIC_SERVLET" -> ".*javax.servlet.GenericServlet.(getInitParameter|getInitParameterNames).*",
    "SERVLET_CONFIG" -> ".*javax.servlet.ServletConfig.(getInitParameter|getInitParameterNames).*",
    "COOKIE" -> ".*javax.servlet.http.Cookie.(getComment|getDomain|getPath|getName|getValue).*",
    "SQL_RESULTSET" -> ".*java.sql.ResultSet.(getString|getObject).*",
    "AWT" -> ".*java.awt.TextComponent.(getSelectedText|getText).*",
    "CONSOLE_READ" -> ".*java.io.Console.(readLine|readPassword).*",
    "INPUTSTREAM" -> ".*java.io.DataInputStream.(readLine|readUTF).*",
    "LINE_READER" -> ".*java.io.LineNumberReader.(readLine).*",
    "HTTP_SESSION" -> ".*javax.servlet.http.HttpSession.(getAttribute|getAttributeNames|getValue|getValueNames).*",
    "SYSTEM" -> ".*java.lang.System.(getProperty|getProperties|getenv).*",
    "PROPERTY" -> ".*java.util.Properties.(getProperty).*",
    "RESOURCE" -> ".*java.lang.Class.(getResource|getResourceAsStream).*",
    "XML_RPC" -> ".*org.apache.xmlrpc.XmlRpcClient.(execute|search).*",
    "XPATH" -> ".*javax.xml.xpath.XPath.(evaluate).*",
    "XPATH_EXPR" -> ".*javax.xml.xpath.XPathExpression.(evaluate).*",
    "RAND" -> ".*java.security.SecureRandom.(<init>).*|.*java.util.Random.(<init>).*",
    "FILE" -> ".*javax.tools.SimpleJavaFileObject.*|.*java.io.File.(<init>).*",
    "CONNECTION_POOL" -> ".*org.apache.commons.dbcp2|com.zaxxer.HikariCP|com.mchange.c3p0"
)

// INITIALIZERS (TRANSFORMERS)
val initializers = Map(
    "CONNECTION_POOL" -> ".*ComboPooledDataSource.*(setDriverClass|setJdbcUrl|setUser|setPassword|setMinPoolSize|setAcquireIncrement|setMaxPoolSize).*",
    "DB" -> ".*HikariConfig.*<init>.*|.*java.sql.Connection.close.*"
)

// SANITIZERS (TRANSFORMERS)
val sanitizers = Map(
    "ESAPI" -> ".*org.owasp.encoder.Encode.(forHtml|forHtmlContent|forHtmlAttribute|forHtmlUnquotedAttribute|forCssString|forCssUrl|forUri|forUriComponent|forXml|forXmlContent|forXmlAttribute|forXmlComment|forCDATA|forJava|forJavaScript|forJavaScriptAttribute|forJavaScriptBlock|forJavaScriptSource).*",
    "ENCODE" -> ".*java.net.URLEncoder.(encode).*",
    "DECODE" -> ".*java.net.URLDecoder.(decode).*",
    "STRING_UTILS" -> ".*org.apache.commons.lang.StringEscapeUtils.(escapeJava|escapeJavaScript|unescapeJava|escapeHtml|unescapeHtml|escapeXml|escapeSql|unescapeCsv).*"
)

// SINKS
val sinks = Map(
    "COMMAND_INJECTION" -> ".*java.lang.Runtime.(exec).*|javax.xml.xpath.XPath.(compile).*|java.lang.Thread.(sleep).*|java.lang.System.(load|loadLibrary).*|java.lang.System.(load|loadLibrary).*|org.apache.xmlrpc.XmlRpcClient.(XmlRpcClient|execute|executeAsync).*",
    "COOKIE_POISON" -> ".*javax.servlet.http.Cookie.(Cookie|setComment|setDomain|setPath|setValue).*",
    "NETWORK" -> ".*java.io.PrintWriter.(print|println|write).*|javax.servlet.ServletOutputStream.(print|println).*|javax.servlet.jsp.JspWriter.(print|println).*|javax.servlet.ServletRequest.(setAttribute|setCharacterEncoding).*|javax.servlet.http.HttpServletResponse.(sendError|setDateHeader|addDateHeader|setHeader|addHeader|setIntHeader|addIntHeader).*|javax.servlet.ServletResponse.(setCharacterEncoding|setContentType).*|javax.servlet.http.HttpSession.(setAttribute|putValue).*",
    "XSS" -> ".*java.io.PrintWriter.(print|println|write).*|javax.servlet.ServletOutputStream.(print|println).*|javax.servlet.jsp.JspWriter.(print|println).*|javax.servlet.ServletRequest.(setAttribute|setCharacterEncoding).*|javax.servlet.http.HttpServletResponse.(sendError|setDateHeader|addDateHeader|setHeader|addHeader|setIntHeader|addIntHeader).*|javax.servlet.ServletResponse.(setCharacterEncoding|setContentType).*|javax.servlet.http.HttpSession.(setAttribute|putValue).*",
    "HTTP_SPLIT" -> ".*javax.servlet.http.HttpServletResponse.(sendRedirect|getRequestDispatcher).*",
    "LDAP_INJECTION" -> ".*javax.naming.directory.InitialDirContext.(InitialDirContext|search).*|javax.naming.directory.SearchControls.(setReturningAttributes|connect|search).*",
    "LOG_FORGING" -> ".*java.io.PrintStream.(print|println).*|java.util.logging.Logger.(config|fine|finer|finest|info|warning|severe|entering|log).*|org.apache.commons.logging.Log.(debug|error|fatal|info|trace|warn).*|java.io.BufferedWriter.(write).*|javax.servlet.ServletContext.(log).*|javax.servlet.GenericServlet.(log).*",
    "PATH_TRAVERSAL" -> ".*java.io.(File|RandomAccessFile|FileReader|FileInputStream|FileWriter|FileOutputStream).*|java.lang.Class.(getResource|getResourceAsStream).*|javax.mail.internet.InternetAddress.(InternetAddress|parse).*",
    "REFLECTION" -> ".*java.lang.Class.(forName|getField|getMethod|getDeclaredField|getDeclaredMethod).*",
    "DBDRIVER" -> ".*java.sql.DriverManager.(getConnection).*",
    "SQL_INJECTION" -> ".*java.sql.(Prepared)?Statement.(addBatch|execute|executeQuery|executeUpdate).*|java.sql.Connection.(prepareStatement|prepareCall|createStatement|executeQuery).*|javax.persistence.EntityManager.(createNativeQuery|createQuery).*|(org|net.sf).hibernate.Session.(createSQLQuery|createQuery|find|delete|save|saveOrUpdate|update|load).*",
    "XPATH_INJECTION" -> ".*javax.xml.xpath.XPath.(compile|evaluate).*|javax.xml.xpath.XPathExpression.(evaluate).*|org.apache.xpath.XPath.(XPath).*|org.apache.commons.jxpath.JXPath.(getValue).*|org.xmldb.api.modules.XPathQueryService.(query).*|org.xmldb.api.modules.XMLResource.(setContent).*",
    "FILE" -> ".*java.io.File.*|java.io.File(read|write|delete).*|java.nio.file.Files.*(write).*",
    "REQUEST_FORWARD" -> ".*RequestDispatcher.*",
    "CLASS_LOADER" -> ".*java.lang.ClassLoader.(defineClass).*",
    "ENCODE" -> ".*java.util.Base64.*(encodeToString).*",
    "DECODE" -> ".*java.util.Base64.*(decode).*",
    "COMPILER" -> ".*javax.tools.JavaCompiler.*(run|getTask).*",
    "LOGGER" -> ".*Logger.(info|warn|debug).*",
    "CRYPTO_INIT" -> ".*javax.crypto.Cipher.init.*",
    "CRYPTO_FINAL" -> ".*javax.crypto.Cipher.doFinal.*",
    "EMAIL" -> ".*javax.mail.internet.MimeBodyPart.*|.*javax.mail.internet.MimeMessage.setContent.*|.*javax.mail.Transport.send.*"
)
