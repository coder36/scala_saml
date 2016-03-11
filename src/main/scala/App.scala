import java.io._
import java.security.cert.{CertPathValidator, CertificateFactory, PKIXParameters, TrustAnchor, X509Certificate => JavaX509Certificate}
import javax.xml.namespace.QName
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

import org.apache.xml.security.utils.Base64
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.opensaml.DefaultBootstrap
import org.opensaml.saml2.core.AuthnRequest
import org.opensaml.security.SAMLSignatureProfileValidator
import org.opensaml.xml.security.x509.BasicX509Credential
import org.opensaml.xml.signature._
import org.opensaml.xml.{Configuration, XMLObject}
import org.w3c.dom.Document

import scala.collection.JavaConversions._

object App {

  val fakeCa =
    """
      -----BEGIN CERTIFICATE-----
      MIIC9jCCAd6gAwIBAgIBATANBgkqhkiG9w0BAQUFADAUMRIwEAYDVQQDEwlkdW1t
      eXByb3YwHhcNMTYwMzExMTU0MzAwWhcNMTcwMzExMTU0MzAwWjAUMRIwEAYDVQQD
      EwlkdW1teXByb3YwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCqYN68
      SRvLZKhlx+H3jmj3bXw/Lrp8zjzHs/W/aUJLV5IgPDub3eCDK40yGNpbGV5m4VPA
      eElyfXMTKfsTvTkUBHuil6vI1R2c7Uo+RKyOulZKGAFrmCQyTvBi7DYNcbPcrPpY
      6uVDJw0TmfH6mjc+cNwXkF8enhSVhuoAOIdfgajNjn10KHVyt5WmKP3Hr4UqlEb1
      AaaPBSYSJW7u/2hb5yk1bOiSSsPvZlpZXCgLaRjoK/cLLiDuAEeCiLKYc0kjH6oV
      q5JW2LA9neqZJdKiQ5vgay67y+9jD3bapvAtB/oJ6w2IV8lUW96WAMWR0/e5x4lk
      Z4psKiVk9ThNQ5fRAgMBAAGjUzBRMA8GA1UdEwEB/wQFMAMBAf8wCwYDVR0PBAQD
      AgEGMBEGCWCGSAGG+EIBAQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRp
      ZmljYXRlMA0GCSqGSIb3DQEBBQUAA4IBAQA8JDV2KHHLxBHZ+DTmq2rWWhUW0l7d
      kAFcMbJE7DBWAAQpnCkdn9jgoPPvGLTzklz3Qqm7GPaUL4EY9tgRzPGH/y2Y9khy
      2MwvXG0gWhtu5aFiLodIwJwxCsNWrWlSC2dYSNlQFvi2fqCJ0WWr2Snyw9nrsd65
      Q3yIOTRaPiXPS5nCZzat8mFEASF3LOdDGxjX3rsjSevPsBltsIMsY4YUGlWT8Tmj
      TPVafrGbWaQYKDELPWYSmumTbiAIsOc1LEcybf9TN4L1STOl32Jx7tv2gSOdfWi1
      /kN01vMDg50GcptR2l4grNP5JD2vt+gPKZjmqF3IBBUThxHtm//yaSov
      -----END CERTIFICATE-----
    """

  val caCert =
    """
      -----BEGIN CERTIFICATE-----
      MIIFNzCCAx+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAlMRIwEAYDVQQHEwlOZXdj
      YXN0bGUxDzANBgNVBAMTBmNhLmdnMzAeFw0xNjAzMTExNDIyMDBaFw0yNjAzMTEx
      NDIyMDBaMCUxEjAQBgNVBAcTCU5ld2Nhc3RsZTEPMA0GA1UEAxMGY2EuZ2czMIIC
      IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAylyZvT5pILQgBUggTzeNW5i9
      Ofgk7pWfZtnil12Hw1RJf6N/G5U77A+K5uAyD3MYRwUqYCkGA3SMlmSl6ju+yuhw
      2tH2zQ/f3uhixeXmWsOCvh4zwFUQginavJuzSH9jI3j59jY3t6VNBnI9TcaxNtZi
      RcOCqFIWCLKpXL/q4JCbDk8e0zkKBM/tZzOVaJ7vhNHn923vQO72SabpFuLz8FCP
      KvIUSItiE+TxZauGa7WS8jj94k9E2bhHUcuiqhIQ4TRk4ZfDx6bT/rksjM/2+E2w
      UHlrCv3cAmcKeRvqQOgghdcEdx7w8D3Nbppeo43vKdRq13Kr8y3uZFh2tOUOBAc+
      +iGxwIBJg6xlJ2kl/B/gtawYUI4Ye0hpaFqGpSBBepB8KtEGrsR25rckeQFjqtsg
      t1nOZxp2th0N5xKUz2T3DoXH1uIva6X/DTe5tUO67ROFdxTUB8W5FHbV6OQcdXmM
      Uh3S26rulLwqrRsuJHeGYhOpFzw+N5TkjMtVZz8iITpd1NxEqTFQHn0mZr3Q3eVL
      WgCilBf2CVFNhxjtPIyX3RewDfqS2Bcz7RB7CUE/A0JVD0EKs37QXvHNp9wzAXJw
      LVtAi+YsQOa3+rHIb31Fb/3c30bWBVubgyvpwjC08bxLy+h1+oAFPU7eOeqERiI1
      GSWfLh7xhVWeSAPadz0CAwEAAaNyMHAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
      FgQUp5xe8eVjBbaeU+NsjWAY/JY08FMwCwYDVR0PBAQDAgEGMBEGCWCGSAGG+EIB
      AQQEAwIABzAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRpZmljYXRlMA0GCSqGSIb3
      DQEBBQUAA4ICAQASBcBx1K2HvDqpuOBzsuuOrBG5A1MmDUPlBe+ba9biCxHbngC3
      m+feyXDMddEmuutXYPd4voh/0+1wyY6kIk1uiJNIP8zW3NXGsC7cxWkyHjwKOuqB
      Iyr5BAF1VsEkO9ArlnnuCiTxEelP4HDVwh0dmLCHtSrCB+U6y/R1s2b0oVx88ki9
      f3VO3h/RW/vP+HcqAMheRrnLjW4phiMMEUt0TUKzLgxhxs7/SCDUPOvH7v8RWH18
      ynoWPcP5zH7OsQJP93U8y4L+JTNCNrFHYb6PU+t0wcwMdh0hrXcj3QWRk+Ut6M9S
      w6Dp/APP4q4NTZDpU615BD3ARBJUVzH4SMC6nXhC6ciLPK1cyfKyAQwEN8nPuJxr
      LELloyyqTHDfZoyu621J/FrGBshTkiy/sWsJ78cdtfGAXT76CRJ64WaWWnrcjiCM
      hgn8DKK0cE/sXu1HRuo7nUog1Jvp+qMref+V6Lc3nqlcBUO5saE1Yp+uASIIyR0/
      l+HuxeMxM2v6JcQEP0H11vQ9WelfcWAQiKL3n8EDbiMpSTtWCxDiS6OpPiyWkQGw
      zYcqUScswZHqf+VfjVOMwTD5t+uO2i+vBSyTkY+O9FURGuRbH+tVLX5J+ExEp/SH
      wu50RrUqeJnf8507KFp0BrxG4E9jHkeVXqAE+Ig0GVYwdor/5ZmTQEPFUw==
      -----END CERTIFICATE-----
    """

  // signed by caCert
  val serviceProviderCert =
    """
      -----BEGIN CERTIFICATE-----
      MIIFNjCCAx6gAwIBAgIBAjANBgkqhkiG9w0BAQUFADAlMRIwEAYDVQQHEwlOZXdj
      YXN0bGUxDzANBgNVBAMTBmNhLmdnMzAeFw0xNjAzMTExNDIzMDBaFw0xNzAzMTEx
      NDIzMDBaMCcxEjAQBgNVBAcTCU5ld2Nhc3RsZTERMA8GA1UEAxMIcHJvdmlkZXIw
      ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDbFdYdUmLF5j9OK8OCILLk
      SBtnYfCi4LJdogQ6h3HzSPBVfMThmIG9zOm42ZBsD7oWahGOCVVfvQfbm7LTSoCO
      LAoIu3m87qIxnAfxWqTudhk/4j5jhyHQpNTuGvHopiQiM9sTiu6rVQzrjCch+H2V
      VZO0V4QILIEgpnfqFA7u8By+Vmo+0N3mBtGenGcdo8Z1ONu/Nd6PPrVCLZtZrx7W
      XWMydKDVRz/GJMoos5j7onorMIhPwHo5mdejRhKX8kQ8X0hla4RUw0pIyXBGPQtw
      +0Bej3pB2h8842dgSDmI6KvnX2pNqhEoc6i0VHsxYTEcF0wuPFYqHD/jMdv9Jiqi
      GCSb6xWYguKtY63julikxy1w6IITqzs56u6oG70o1aToaFujnlZ3DvXZ9u4M0oXD
      bkTDkbMLtKwGHX86OKKjhK5GJRp+WNaaP5siscgigdjPp83cM9dzl37kEbwbmLyH
      65sUBLBFHasDBhAb1Ah57Pqxx9HWhVaUyIT7812RZwxVvMU8uQvCXYINCGT1EyB/
      CQaNBmcSG15Oh9HMgg2++P9DGD//x6O/2b3GviiqEM4vAm9LodLRnzooSYEBEvvS
      8als4OaS3e+WjQnhWeBFDykHgKUsdZ9dV7OdaQhjuQzBf9jFTfcC6AgFA24/NoLt
      JyDwJ1npeh81+64aVavoTQIDAQABo28wbTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
      BBQu9T5EgLfA4YVn68bnm5HG6WAX7DALBgNVHQ8EBAMCBeAwEQYJYIZIAYb4QgEB
      BAQDAgZAMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcN
      AQEFBQADggIBALa1WCD9YExM0h53Vhz0iXiuJJcI+adcnr6lDDIv0KGMY4N1bfmS
      1mQMVrdB2Qoyi0RBDE8dy01mwyAsBuNTvgEQe83ayLWWwlCxvPOpP9Mmez7lWEr2
      zb5Ky39mivh6jyr9R0cUBDnPMq6/hpbRrUuwYSV+N8DBkFMFWTyPNAJXydQ4a4AW
      33piGCM2KICRmbpbhPycix6vSrXuAUWxGPPMM5y2JRTGBTFvwhse9qoM/JpE1foW
      34JwzrnQMTbv5yK8jYgJEov6bQXdpTu9QIBRIXoEUkIuKaLGgSiEAOvYWpBVUE3h
      VjAtcYIaEXww4T5qslR5hwpzGnDhUcyYSqjPQ0kbUKJFLXA+ggysD7SXSpiKBpHQ
      zK7hVTP5HYaCGW2H+MVRNy13qPS7mcXXAihOHVuRybAcMne5+c0cImWuZoLiHTuW
      W/UxwCR1GSaSInZJJDC8GYyJZYvXPrzkJVBErf32kthVUxPbt8Vumvoq4vKxl7vf
      YWzOvW4dO3+UNiGSu02yykGeYgjralQrkk1BhxIwxAYciQaVmA/nRkhXH1WFsj65
      zmW68e/n5zyKKINW/xMfutMvaJtALGvlxLcnpmHL2fwmOeTYvspUzdQKq359dBAM
      O5fGFhDNGp4zNVF381jssOf8mVAz9wFlDmRQIXJMT9GczEFm9vLs/W+H
      -----END CERTIFICATE-----
    """


  val serviceProviderCertPrivateKey =
    """
      -----BEGIN PRIVATE KEY-----
      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
      wPcVEK1YzQXcBpqoOY0Bc72/OQzqIeo=
      -----END PRIVATE KEY-----
    """


  def main(args: Array[String]) : Unit = {
    val s = SAMLUtil.createAuthnRequest( serviceProviderCert, serviceProviderCertPrivateKey )
    println(s)
    SAMLUtil.validate(s, caCert) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature )
  }


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

      signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA)
      signature.setSigningCredential(credential)
      signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS)
      signature.setKeyInfo(keyInfo)
      keyInfo.getX509Datas.add(x509Data)
      x509Data.getX509Certificates.add( x509Certificate )
      x509Certificate.setValue(Base64.encode(credential.getEntityCertificate().getEncoded()))

      authnRequest.setID("AAA")
      authnRequest.setDestination("http://aa.cc.vv")
      authnRequest.setSignature(signature)

      sign(authnRequest, signature )
    }


    def validate(rawSaml: String, caCert: String)(getSignature: (XMLObject) => Signature ) : Unit = {

      // structual validation
      val sig = getSignature(read(rawSaml))
      new SAMLSignatureProfileValidator().validate(sig)

      val sigingCert = parseCertificate(s"""
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
      sigingCert.checkValidity()

      // certificate chain validation
      val params = new PKIXParameters(Set(new TrustAnchor(parseCertificate( caCert ), null)))
      params.setRevocationEnabled(false)
      val certFactory = CertificateFactory.getInstance("X509")
      val certPath = certFactory.generateCertPath(List(sigingCert))
      val pathValidator = CertPathValidator.getInstance("PKIX")
      pathValidator.validate(certPath, params)

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


    private def read( saml : String ) : XMLObject = {
      val doc = documentBuilderFactory.newDocumentBuilder().parse( new ByteArrayInputStream(saml.getBytes) ).getDocumentElement()
      Configuration.getUnmarshallerFactory().getUnmarshaller(doc).unmarshall(doc)
    }

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


  }

}
