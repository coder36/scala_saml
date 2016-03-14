import java.io._
import java.nio.charset.StandardCharsets
import java.security.cert.{CertPathValidator, CertificateFactory, PKIXParameters, TrustAnchor, X509Certificate => JavaX509Certificate}
import javax.xml.namespace.QName
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.opensaml.DefaultBootstrap
import org.opensaml.saml2.core.AuthnRequest
import org.opensaml.security.SAMLSignatureProfileValidator
import org.opensaml.xml.security.x509.BasicX509Credential
import org.opensaml.xml.signature._
import org.opensaml.xml.{Configuration, XMLObject}
import org.w3c.dom.Document
import java.util.{Base64, UUID}

import scala.collection.JavaConversions._


object SAMLUtil extends SAMLUtil {
  DefaultBootstrap.bootstrap()
}

class SAMLUtil {

  val documentBuilderFactory = DocumentBuilderFactory.newInstance()
  documentBuilderFactory.setNamespaceAware(true)


  def createAuthnRequest( signingCert: String, signingKey: String) : String = {

    val authnRequest = create[AuthnRequest](AuthnRequest.DEFAULT_ELEMENT_NAME)
    val signature = create[Signature](Signature.DEFAULT_ELEMENT_NAME)
    val keyInfo = create[KeyInfo](KeyInfo.DEFAULT_ELEMENT_NAME)
    val x509Data = create[X509Data](X509Data.DEFAULT_ELEMENT_NAME)
    val x509Certificate = create[X509Certificate](X509Certificate.DEFAULT_ELEMENT_NAME)
    val credential = createSigningCredential( signingCert, signingKey)

    signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512)
    signature.setSigningCredential(credential)
    signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
    signature.setKeyInfo(keyInfo)
    keyInfo.getX509Datas.add(x509Data)
    x509Data.getX509Certificates.add( x509Certificate )
    x509Certificate.setValue(Base64.getEncoder().encodeToString(credential.getEntityCertificate().getEncoded()))

    authnRequest.setID(UUID.randomUUID.toString)
    authnRequest.setDestination("http://aa.cc.vv")
    authnRequest.setSignature(signature)

    sign(authnRequest, signature )
  }


  def validate(rawSaml: String, caCert: String)(getSignature: (XMLObject) => Signature ) : Symbol = {
    try {
      // structual validation
      val sig = getSignature(read(rawSaml))
      new SAMLSignatureProfileValidator().validate(sig)

      val sigingCert = parseCertificate(
        s"""
          -----BEGIN CERTIFICATE-----\n
          ${sig.getKeyInfo.getX509Datas.get(0).getX509Certificates.get(0).getValue}
          \n-----END CERTIFICATE-----
        """)

      // validate saml signature
      val b = new BasicX509Credential()
      b.setEntityCertificate(sigingCert)
      val sigValidator = new SignatureValidator(b)
      sigValidator.validate(sig)

      // validate certificate
      sigingCert.checkValidity

      // certificate chain validation
      val params = new PKIXParameters(Set(new TrustAnchor(parseCertificate(caCert), null)))
      params.setRevocationEnabled(false)
      val certFactory = CertificateFactory.getInstance("X509")
      val certPath = certFactory.generateCertPath(List(sigingCert))
      val pathValidator = CertPathValidator.getInstance("PKIX")
      pathValidator.validate(certPath, params)
      'ok
    }
    catch {
      case ex: java.security.cert.CertPathValidatorException => 'untrusted_cert
      case ex: java.security.cert.CertificateExpiredException => 'expired_cert
      case ex: Throwable => 'saml_validation_failed
    }
  }

  def read( saml : String ) : XMLObject = {
    val doc = documentBuilderFactory.newDocumentBuilder().parse( new ByteArrayInputStream(saml.getBytes) ).getDocumentElement()
    Configuration.getUnmarshallerFactory().getUnmarshaller(doc).unmarshall(doc)
  }

  private def createSigningCredential( singingCert: String, signingKey: String = null) : BasicX509Credential = {

    val credential = new BasicX509Credential()
    credential.setEntityCertificate(parseCertificate( singingCert ))

    val k = new PEMParser(new StringReader(signingKey.trim) ).readObject().asInstanceOf[org.bouncycastle.asn1.pkcs.PrivateKeyInfo]
    credential.setPrivateKey(new JcaPEMKeyConverter().getPrivateKey(k))
    credential
  }

  private def parseCertificate( cert: String ): JavaX509Certificate = {
    val cf = CertificateFactory.getInstance("X.509")
    cf.generateCertificate(new ByteArrayInputStream(cert.trim.getBytes)).asInstanceOf[JavaX509Certificate]
  }


  private def create[T](elementName: QName): T = Configuration.getBuilderFactory.getBuilder(elementName).buildObject(elementName).asInstanceOf[T]


  private def marshal(xml: XMLObject) : Document = {
    val responseMarshaller = Configuration.getMarshallerFactory().getMarshaller(xml)
    val document = documentBuilderFactory.newDocumentBuilder().newDocument()
    responseMarshaller.marshall(xml, document)
    document
  }

  private def sign( xml: XMLObject, signature: Signature ): String = {
    val document = marshal(xml)
    Signer.signObject(signature)
    val docWriter = new StringWriter
    TransformerFactory.newInstance.newTransformer.transform(new DOMSource(document), new StreamResult(docWriter))
    docWriter.toString
  }

  private def encode(saml: String) : String = {
    Base64.getEncoder().encodeToString(saml.getBytes(StandardCharsets.UTF_8))
  }

  private def decode(b64saml: String) : String = {
    Base64.getDecoder().decode(b64saml).toString
  }

}