package saml.saml;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.Base64;
import java.util.UUID;
import java.util.Properties;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.net.URLEncoder;
import org.w3c.dom.Element;

import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.xml.util.XMLHelper;

/**
 * SAML Request Generator
 *
 */
public class ADFSSAMLRequestGen 
{				
	private static ADFSSAMLRequestGen requestGen;

	private static Properties properties = new Properties();

	private String logData = "";

	private ADFSSAMLRequestGen() {
    	try {
			logData += "Initialising the new SAML request\r\n";
			
			properties.load(new FileInputStream("c:/psft/cfg/saml/saml.properties"));

			logData += "Configuration loaded\r\n";

			InitializationService.initialize();

			logData += "Completed initialization\r\n";

		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logData += sw.toString();
        }
	}

	public static ADFSSAMLRequestGen GetInstance() throws FileNotFoundException, IOException {
		if (requestGen == null) {
			requestGen = new ADFSSAMLRequestGen();
		}

		return requestGen;
	}

	public String buildRequest() {
		try {
			logData = "Starting build request\r\n";
			AuthnRequest authnRequest = buildAuthnRequest();

			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(authnRequest);
			Element element = marshaller.marshall(authnRequest);

			logData += "Marshalled AuthnRequest\r\n";

			StringWriter writer = new StringWriter();
			XMLHelper.writeNode(element, writer);
			String xmlString = writer.toString();

			logData += "Encoding XML: " + xmlString + "\r\n";

			Deflater deflater = new Deflater(Deflater.DEFLATED, true);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
			deflaterOutputStream.write(xmlString.getBytes());
			deflaterOutputStream.close();
			String encodedRequestMessage = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
			String encodedAuthnRequest = URLEncoder.encode(encodedRequestMessage,"UTF-8").trim();
			return encodedAuthnRequest;
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logData += sw.toString();
			return "";
		}
	}

	public String getDestination() {
		return properties.getProperty("ssoDestination");
	}

	private AuthnRequest buildAuthnRequest() {
		String uid = UUID.randomUUID().toString();
		logData += "UUID: " + uid + "\r\n";
		AuthnRequestBuilder builder = new AuthnRequestBuilder();
		AuthnRequest authnRequest = builder.buildObject();
		authnRequest.setIssueInstant(Instant.now());
		authnRequest.setDestination(properties.getProperty("ssoDestination"));
		logData += "SSO Destination: " + properties.getProperty("ssoDestination") + "\r\n";
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(properties.getProperty("consumerServiceURL"));
		logData += "Consumer Service URL: " + properties.getProperty("consumerServiceURL") + "\r\n";
		authnRequest.setID("id_" + uid);
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		Issuer authIssuer = new IssuerBuilder().buildObject();
		authIssuer.setValue(properties.getProperty("spid"));
		authnRequest.setIssuer(authIssuer);

		NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
		//nameIDPolicy.setAllowCreate(true);
		nameIDPolicy.setFormat(NameIDType.UNSPECIFIED);
		authnRequest.setNameIDPolicy(nameIDPolicy);

		logData += "Completed AuthnRequest building\r\n";

		return authnRequest;
	}

	public String getLogData() {
		return logData;
	}
}
