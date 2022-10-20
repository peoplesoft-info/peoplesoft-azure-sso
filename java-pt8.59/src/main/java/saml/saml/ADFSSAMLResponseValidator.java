package saml.saml;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.StringWriter;
import java.io.PrintWriter;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Properties;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import com.google.common.collect.ImmutableList;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.metadata.resolver.impl.AbstractBatchMetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FileBackedHTTPMetadataResolver;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.RoleDescriptor;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.P;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

/**
 * Hello world!
 *
 */
public class ADFSSAMLResponseValidator 
{				
	private static ADFSSAMLResponseValidator validator;
	
	private FileBackedHTTPMetadataResolver metadataResolver;
	
	private UnmarshallerFactory unmarshallerFactory;
	
	private DocumentBuilder docBuilder;
	
	private Properties properties = new Properties();
	
	private String logData = "";

    private ADFSSAMLResponseValidator() throws FileNotFoundException, IOException
    {
    	
    	logData += "Initialising the ADFSSAMLResponseValidator\r\n";
    	
    	properties.load(new FileInputStream("c:/psft/cfg/saml/saml.properties"));

    	try {
			logData += "Initialising the OpenSAML InitializationService\r\n";
			InitializationService.initialize();
			
			logData += "Finished initializing the InitializationService\r\n";

	    	HttpClient httpClient = HttpClientBuilder.create().build();
	    	
	    	metadataResolver = new FileBackedHTTPMetadataResolver(httpClient, properties.getProperty("federationUrl"), properties.getProperty("metadataCachePath"));
	    	metadataResolver.setId(properties.getProperty("spid"));
			logData += "federationURL: " + properties.getProperty("federationUrl") + "\r\n";
			logData += "metadataCachePath: " + properties.getProperty("metadataCachePath") + "\r\n";
			logData += "spid: " + properties.getProperty("spid") + "\r\n";
	    	BasicParserPool pp = new BasicParserPool();
	    	pp.initialize();
	    	
	    	metadataResolver.setParserPool(pp);
	    	
			logData += "Initialising the OpenSAML FileBackedHTTPMetadataResolver\r\n";
	    	metadataResolver.initialize();
			logData += "Finished initialising the OpenSAML FileBackedHTTPMetadataResolver\r\n";
	    	
	    	DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        	documentBuilderFactory.setNamespaceAware(true);
        	docBuilder = documentBuilderFactory.newDocumentBuilder();
        	
        	unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        	
			logData += "Finished initialising the ADFSSAMLResponseValidator\r\n";
        		    	
		} catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logData += sw.toString();
		}
    	 	
    }
    
    public static ADFSSAMLResponseValidator GetInstance() throws FileNotFoundException, IOException {
    	if (validator == null) {
    		validator = new ADFSSAMLResponseValidator();
    	}
    	
    	return validator;
    }
	
	public String getLogData() {
		return logData;
	}
    
    public boolean ValidateSAMLResponse(String SAMLResponse) {

    	try {
    		
			logData = "Parsing the SAMLResponse input:\r\n";
			logData += SAMLResponse + "\r\n";
			
        	Document document = docBuilder.parse(new ByteArrayInputStream(SAMLResponse.getBytes()));
        	Element element = document.getDocumentElement();
        	Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        	
			logData += "Unmarshalling the SAMLResponse\r\n";
        	XMLObject responseXmlObj = unmarshaller.unmarshall(element);
        	        	
        	Response response = (Response) responseXmlObj;
        	
        	Assertion ass = response.getAssertions().get(0);
        	
        	response.getAssertions().get(0).getDOM().setIdAttribute("ID", true);

	    	CriteriaSet cs = new CriteriaSet( new EntityIdCriterion(properties.getProperty("trustEntity")));        	
			logData += "Trust entity: " + properties.getProperty("trustEntity") + "\r\n";
			logData += "Retrieving Identity Provider metadata\r\n";
	    	Iterable<EntityDescriptor> result = metadataResolver.resolve(cs);

			logData += "Finding match for public key in SAML response\r\n";
        	for (EntityDescriptor ed: result) {
				logData += "Found an entity descriptor result\r\n";
        		for (KeyDescriptor kd: ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS).getKeyDescriptors()) {
					logData += "Found a key descriptor\r\n";
        			for(X509Data xd: kd.getKeyInfo().getX509Datas()) {
        				for(X509Certificate xc: xd.getX509Certificates()) {
        					        					
        					if(xc.getValue() == ass.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue()) {
								logData += "Found a public key match between SAMLResponse and metadata\r\n";
        						
        						X509Certificate cf = ass.getSignature().getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
        						
        						String lexicalXSDBase64Binary = cf.getValue();
        						byte[] decodedString = Base64.getDecoder().decode(new String(lexicalXSDBase64Binary).getBytes("UTF-8"));
        						
        						CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        						java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(decodedString));
        		                
        						BasicX509Credential cred = new BasicX509Credential(cert);
        						
								logData += "Validating SAMLResponse with public key\r\n";
        						
        						SignatureValidator.validate(response.getAssertions().get(0).getSignature(), cred);
        						
								logData += "SAMLResponse successfully validated with public key\r\n";
        						
        						return true;
        					} else {
								logData += "Found a public key mismatch\r\n";
							}
        				}
        			}
        		}
        	}
        	
			logData += "Unable to find matching public key for SAMLResponse\r\n";
        	
        	return false;   	
        } catch (Exception e) {
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			logData += sw.toString();
        	return false;
        }
    }
}
