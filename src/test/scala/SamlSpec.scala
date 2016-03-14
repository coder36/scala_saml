import org.opensaml.saml2.core.{Attribute, Assertion, AuthnRequest, Response}
import org.scalatest.{FlatSpec, Matchers}
import scala.collection.mutable.{Map => mMap}
import scala.collection.JavaConversions._

class SamlSpec extends FlatSpec with Matchers {


  val fakeCaCert =
    """
      -----BEGIN CERTIFICATE-----
      MIIFTTCCAzWgAwIBAgIBATANBgkqhkiG9w0BAQUFADAwMRwwGgYDVQQHExNOZXdj
      YXN0bGUgdXBvbiB0eW5lMRAwDgYDVQQDEwdjYS5mYWtlMB4XDTE2MDMxNDA5MzQw
      MFoXDTI2MDMxNDA5MzQwMFowMDEcMBoGA1UEBxMTTmV3Y2FzdGxlIHVwb24gdHlu
      ZTEQMA4GA1UEAxMHY2EuZmFrZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
      ggIBAOfs0fL5VaomHUSBkaoraNQry0TZwKEOnvjmvoSSDdttAyye1f3TuKpWShD8
      XuK1zT1Fo5RC2lnVQK4jpL13P9cvdS47H6ea4xiiaMBnPrCE0YPFc3rpRRyR9n6Q
      YhBZVyGCs2eEgLArv/etW+qfJqwpUZXXkB/LMWmR0eelv6/HyrCluIS+Hveb1tBU
      ktUQAaqva7zc8ZHG+8vvtxGehv9b3DnfpVJT2kNDET2+z3xxzFqO9FfZmnx0hxKP
      IdH3Qv+8NEPxYyjPoxZHClkU10No93QHnqhVDH2Hs1CCtpCvbAQAF3jccRn0cAIb
      ojQy04qPgOA8c/N9w1qY8+lIUR7s2lLYC/qvKoGTJ/uSrJ2/x7w0/KO9Em/E1/db
      hXN8rNRW00eV/2QsrXCjhRvYDUT7INB8cKBp0fSVLGF1JFRs0aqGyC34oet4BQc6
      VIiez+sDBGr3aTBv1+G1nP+TZQthxNWnM4t07656OZXts2+Hlw59Ro+mewHWMwI/
      VO8zuNcpFrCp4DsAR3C3WSCfp1wKVSu6nfW0aHNQFeIXjXmY6msx3JvkBq+dRBSX
      3iad64uxPAXap6hKOrN+PLmhGSmKkTO7gMLS8BMGTtI6Kf8b2K7IwD8GFU634cxl
      rata2kVJAwMbqiOs5GW67vn0sk9gZl07SjU08p9ILlihPOC9AgMBAAGjcjBwMA8G
      A1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFICQwxP+FazIEYRTdiSJDfIlOe4IMAsG
      A1UdDwQEAwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hj
      YSBjZXJ0aWZpY2F0ZTANBgkqhkiG9w0BAQUFAAOCAgEANTTmhv74A9aReyXUIxr5
      yKsZXIcGW2/8k9zjqG2zd+JBKPDjtn0qbUJ0nbhwskdR+qodwG5dRK5wTKXJdJhd
      D5weBo1uw61jlUte2We9jjBBm43iNFWJ4uj5D9vrZ46kt44zTZsgbFzjV/UjGT44
      Vq7ExEVb+NcEeYujQNJAg428y+vqB8zSVLUCFmv4+md93Xcaf+8wP+fY+kEY00Zw
      AD86mXQNiN7wR/ol/kUCQEYSAwaaVSvoMQDi8i2o9iLei+jRT1jNpE+IK1n/GuBK
      fmI/3Sny1R/W2LrG1TyJPkLgTratkuhZyVtJ/HEbefRK3gn5ydyBxiqf8zALJ1xb
      +lGyPNBeM6RIG2IsIp0WmELIrG3HW+rrXt+XQ+L0rE92fTEhXgRloj9fjxhYxyxU
      16kg3HeI+RGWl0MO9QvFKN6TpKVx8T5DMBis58/cEECthaZUuqYZUkwbXm75Kcu7
      SkvsoadByZCts1eSIMPoze+fAbs7nv3yksv8nbTMDWEiiM4Lo/6x7fRICyNZ8tWI
      sOhOROq3D7XgJ4J8T8+GhSbvgoJDqJs+kmWVSc4JSwfm38CLRTwPdScFdpSpe94t
      YG09JJG4rratbxfQqCqkcueqf+jZ/M/4BoSZWf3AHHGSNyIaEjvKafK3yE7SLNkW
      CFc75Hn5V7itTROeofgdDmk=
      -----END CERTIFICATE-----
    """

  // signed by fakeCaCert
  val fakeServiceProviderCert =
    """
      -----BEGIN CERTIFICATE-----
      MIIEEzCCAfugAwIBAgIBAzANBgkqhkiG9w0BAQUFADAwMRwwGgYDVQQHExNOZXdj
      YXN0bGUgdXBvbiB0eW5lMRAwDgYDVQQDEwdjYS5mYWtlMB4XDTE2MDMxNDA5Mzcw
      MFoXDTE3MDMxNDA5MzcwMFowGDEWMBQGA1UEAxMNcHJvdmlkZXIuZmFrZTCCASIw
      DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALZE511jZdt1RuQfp5P7yT4Q1Wfg
      Cl/iJxum9z7zwIE/4k0ZnmtaiSa5M55zMBQDix4BhkgEHWI26IEo+fGqDquhHrUK
      rXRn3HdsaX27Hf/bJKcXdeOQA7pMLuZ14hJkL4o5yoW2hFy/AToYDQzIskY2eyqs
      jAm6ba8W+dHIhaUSXBnA8CEp6jeup+XcNAdNwwXCEjgSoLNUqi5HETO/jvI3rGqG
      w5bxStpexcZHm26XVZLVVNR7o6NTWUjWf8LiuDAitPcYT/6eRO4DGK3soSQVMxDS
      5SUsUr67W7g7DepMKtJNfO2GgWw23qAvr2hIhA42cy3PPKSPN8BYddaPBOcCAwEA
      AaNQME4wDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBLAwEQYJYIZIAYb4QgEBBAQD
      AgWgMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQEF
      BQADggIBAKNxuXFK/GadOT1KWR5UoSCAToorKLUah91b+vKhcBCWYcRzOf2bKZCF
      2WzZODyUNUtSl+kFTK+VRLud6jZOD98Cg2L9O0uo9jZmE0TdD1gvsXBDsb4Ra3MC
      M2yyATCnFSEwXHfBB7UEkV5lAnAVmOju9Dx6k4eqrnd2Vw6Skc9mJktFLxHt7D2c
      75+f6ODHI7l/EamBiTSkvwa3dPyJumwBSH1L+Zlz5XblWHQtwmDX043Rz39BnodH
      kVbANdI7cEEvH6IYSN1zmbgo+CUr6NMm+tYT7dfu6VkMQZui1tMmwtEfGa76RPm0
      fP47r9jFrRFPALMxXhYmyYH5GrJ7j2BAD4+pSUjBMKSgfPyRKQgEFdB1bdRTFK0m
      hrentA6iiBj3sII5bNzD8EcHjji9hLsme5DqaQAbXKTzCF10RpDdZHfgyoszBKfZ
      l3BIqTolgabhQx/H1zbnmWy2uP6RZdchnzm/LZRJGMihSiUFu7Rb2qqLAIFXYvS7
      ehbhAU56rL8/QM4aIzeiQ6E/OvxjI2jIzSJAz9U4oArtd+KSZu8RVkWyWYZq6F7P
      81F+a4nFVOA6Rv83eGtW7z4mjvIZVig3JATj9TOTNVYgORNvX7BNTI3OQscXcTl5
      Y9Ts5TxQhn2T/HyqixN1r3TeZC49CWKUSB+KPLBHV+QmKXqDJKvf
      -----END CERTIFICATE-----
    """

  // signed by fakeCaCert
  val fakeServiceProviderKey =
    """
      -----BEGIN PRIVATE KEY-----
      MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2ROddY2XbdUbk
      H6eT+8k+ENVn4Apf4icbpvc+88CBP+JNGZ5rWokmuTOeczAUA4seAYZIBB1iNuiB
      KPnxqg6roR61Cq10Z9x3bGl9ux3/2ySnF3XjkAO6TC7mdeISZC+KOcqFtoRcvwE6
      GA0MyLJGNnsqrIwJum2vFvnRyIWlElwZwPAhKeo3rqfl3DQHTcMFwhI4EqCzVKou
      RxEzv47yN6xqhsOW8UraXsXGR5tul1WS1VTUe6OjU1lI1n/C4rgwIrT3GE/+nkTu
      Axit7KEkFTMQ0uUlLFK+u1u4Ow3qTCrSTXzthoFsNt6gL69oSIQONnMtzzykjzfA
      WHXWjwTnAgMBAAECggEAaMTslPK4rtAXwrMrWVXGlIWKlZ3jeL//KNbtkeL8yY6W
      HylVtXGiGn8kW7TscuSih8nqjOTImxbiyLNsEGxm6GLByuDrWVkGEiNf8+Sl1tb5
      l45VtkumyORXpSMnotixtuuHLRr/tGwaYXFHtwx55QAWBi6OhF0EBTvYt6xincIa
      Q+dURNl2FAXQd3GS5KBPqWutp/cQpjBBeWdH2rYbAOEo+mJ6m2tgEeCjLLw+xv14
      ykAXyqBQAJaMQBo3WtNeGkhLfyAOuh3xnB9xmGNp5tWQtTSXicKfqy1eOeDPlkdY
      qm8hv+XUOihEdWyb/93KZ+PFJl2w8D7amXu75rCCYQKBgQDjYZHBN76ZwqxxGlcU
      4wFkEDQen0Be9I5aH3QGXFeXnNdvbrVjxpupmvBeY0tPR9LQlfYOOGDrdQrYoyUt
      ODMyZ5ykxfSyj0VmYDR5osnluHr42xL3Bs75B+tSkqvLEZi4QTr/qsEh+RBvm9D/
      zfijBR5vZP8+9MooHdlfkBxcVwKBgQDNNcjoONCf75+xmtCquv92WE6Wj0uxAJkm
      o/wBRDENXX0l42Qexec7ErKCgXRabXRhKbDCVXSu5EuAIhWaZ9+OEBRYiu05LxUo
      uLU20b8A6UdPQ7g4Ay5LVDo8YK6IG4DAjHBezyb1O8MR4meUH+ckZzuvXhnboIkH
      c1GNqKZB8QKBgCMGUXxQyORIb2WQqB9IhFtUf6LD5xd5VkAdnjKooLly6GB6zigL
      XMj4W9Q+OUiCCMAmiVtRZeR/B+es4bogcQpvmVpsP7ANj6QgZ5Tg9XaUPyT8IeS5
      QMJtbNswSpQiJsMjESJ2u/8urVBz0PLGWGlMDY8dIJAjBsy9JFGrEiNLAoGBAKox
      m2kOBek/wcB5V+rhoJI0dyljuzEX/+0OQCmEtvIQwYS07QqgtEBIJ4kZeLiu4sDa
      5OCoI1gRu5SPsD8ZO04Fg/pTbp/orrHRT2oh1zoYP647ygOaj8CmII6G2PnFZalM
      UL4xLGxjnkus7J7rPrbwb43oi6WdpUhqmg7U+t7hAoGBAKufvb0RkgsoYCK7J9cj
      2RVrvWS2/pDgzAr1C0blqRDM53gETR+S7GJwfcDwa6FrxxK76plgxm/YAE3CvOE3
      KlNpakIZkBHimuD8CZMij9AYgyDxM2rAyHt+0u2EtTRqD1uTFGbjjsb12IrjIfcN
      aS50PKDmhpsQ9achquWRRvZM
      -----END PRIVATE KEY-----
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
  val expiredCert =
    """
      -----BEGIN CERTIFICATE-----
      MIIFFjCCAv6gAwIBAgIBBjANBgkqhkiG9w0BAQUFADAlMRIwEAYDVQQHEwlOZXdj
      YXN0bGUxDzANBgNVBAMTBmNhLmdnMzAeFw0xNjAzMTQxMDQ2MDBaFw0xNjAzMTQx
      MDQ3MDBaMCYxEjAQBgNVBAcTCW5ld2Nhc3RsZTEQMA4GA1UEAxMHZXhwLmdnMzCC
      AiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsV1h1SYsXmP04rw4IgsuRI
      G2dh8KLgsl2iBDqHcfNI8FV8xOGYgb3M6bjZkGwPuhZqEY4JVV+9B9ubstNKgI4s
      Cgi7ebzuojGcB/FapO52GT/iPmOHIdCk1O4a8eimJCIz2xOK7qtVDOuMJyH4fZVV
      k7RXhAgsgSCmd+oUDu7wHL5Waj7Q3eYG0Z6cZx2jxnU427813o8+tUItm1mvHtZd
      YzJ0oNVHP8YkyiizmPuieiswiE/AejmZ16NGEpfyRDxfSGVrhFTDSkjJcEY9C3D7
      QF6PekHaHzzjZ2BIOYjoq+dfak2qEShzqLRUezFhMRwXTC48ViocP+Mx2/0mKqIY
      JJvrFZiC4q1jreO6WKTHLXDoghOrOznq7qgbvSjVpOhoW6OeVncO9dn27gzShcNu
      RMORswu0rAYdfzo4oqOErkYlGn5Y1po/myKxyCKB2M+nzdwz13OXfuQRvBuYvIfr
      mxQEsEUdqwMGEBvUCHns+rHH0daFVpTIhPvzXZFnDFW8xTy5C8Jdgg0IZPUTIH8J
      Bo0GZxIbXk6H0cyCDb74/0MYP//Ho7/Zvca+KKoQzi8Cb0uh0tGfOihJgQES+9Lx
      qWzg5pLd75aNCeFZ4EUPKQeApSx1n11Xs51pCGO5DMF/2MVN9wLoCAUDbj82gu0n
      IPAnWel6HzX7rhpVq+hNAgMBAAGjUDBOMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD
      AgSwMBEGCWCGSAGG+EIBAQQEAwIFoDAeBglghkgBhvhCAQ0EERYPeGNhIGNlcnRp
      ZmljYXRlMA0GCSqGSIb3DQEBBQUAA4ICAQAviZ6htn3FQz2DQeaNue5DW7xHSBz6
      lyxG2iioYjutl/Vg8RcDR5D4u6ZviDWmWtUXmU3aJYpEki4me/KERr92nBs2x5pD
      VYYf22Jbm7zdmthOHdzOZn+OAMxdCCC/PCJHaViuNzNM18xXy07t4iHl7gd4v7QX
      3yAIHHm+2ikamlQvpCsxuE0mcwleTunz98eSXFa/sU3ANsg52asCzR2Y5kPDUZin
      KUlBC7HFfVIHytYDZwNizBCO0WcOLqvjm8VSpDKRQqYgZAVgu+9wVqTfUMx2DJhM
      kPVIH7Q5Tkpqk49l9gooCYgteWmda0fXoARRz0mTQ6o7gcUWWlAPmMb32DkM15Sn
      b/9i7bBnhKPnVpdr21upe/02O4Ypif3HebsxLshOIcUqgo/QSfS/d4Pj984Sdzzc
      b7kwoz1/yphW8cMuH3myqkLqNL9EFHFWlFHWO3pE6AFAovRaN26faUDvQpAjItRf
      NiWhpLdeXu6FKqAZvCKT0w3u6zeTEH1pfkb+Clwa2YjdOJt/9HTbJ47nZqatxsEL
      6eXWJwYAHOSYtCVwei46idYLU4cWtEGmhvnRMqEIz0w+Jj4xB2P0j3rjV1m2OziP
      /z9WfQcOzq/ckJO3beC0Oh4ZmCIAQ9d3vGBHnEJr0KjqX3X1X6oI3Jbvx3XEmyIK
      TOcD97BTzt0U2A==
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


  def createAuthnRequest(): String = {
    SAMLUtil.createAuthnRequest( serviceProviderCert, serviceProviderCertPrivateKey)
  }


  "SAMLUtil.createAuthnRequest" should "create authentication requests" in {
    val xml = createAuthnRequest
    val req = SAMLUtil.read( xml ).asInstanceOf[AuthnRequest]
  }


  it should "have a signature generated using rsa-sha512" in {
    val saml = SAMLUtil.read( createAuthnRequest ).asInstanceOf[AuthnRequest]
    saml.getSignature.getSignatureAlgorithm should include("rsa-sha512")
    val signingCert = saml.getSignature.getKeyInfo.getX509Datas.get(0).getX509Certificates.get(0)
    normalize(serviceProviderCert) should be(signingCert.getValue)
  }

  it should "create a valid signature" in {
    val saml = createAuthnRequest
    SAMLUtil.validate(saml, caCert ) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature ) should equal('ok)
  }

  it should "fail validation when certificate not signed by trusted ca" in {
    val saml = SAMLUtil.createAuthnRequest( fakeServiceProviderCert, fakeServiceProviderKey)
    SAMLUtil.validate(saml, fakeCaCert ) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature ) should equal('ok)
    SAMLUtil.validate(saml, caCert ) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature ) should equal('untrusted_cert)
  }

  it should "fail validation when certificate has expired" in {
    val saml = SAMLUtil.createAuthnRequest( expiredCert, serviceProviderCertPrivateKey )
    SAMLUtil.validate(saml, caCert ) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature ) should equal('expired_cert)
  }

  it should "fails validation when signature not valid" in {
    val saml = SAMLUtil.createAuthnRequest( serviceProviderCert, serviceProviderCertPrivateKey ).replaceFirst(
      "<ds:SignatureValue>", "<ds:SignatureValue>THIS_IS_AN_INVALID_SIGNATURE" )

    SAMLUtil.validate(saml, caCert ) ((xml) => xml.asInstanceOf[AuthnRequest].getSignature ) should equal('saml_validation_failed)
  }



  "SAMLUtil.createResponse" should "create saml responses" in {
    val saml = SAMLUtil.createResponse( serviceProviderCert, serviceProviderCertPrivateKey, Map())
    SAMLUtil.validate(saml, caCert ) ((xml) => xml.asInstanceOf[Response].getSignature ) should equal('ok)
  }

  "SAMLUtil.extractResponse" should "extract a Map of values" in {
    val saml = SAMLUtil.createResponse( serviceProviderCert, serviceProviderCertPrivateKey, Map("xxx" -> "yyy", "aaa" -> "bbb"))
    val resp = SAMLUtil.read(saml).asInstanceOf[Response]

    val attributes = resp.getAssertions.headOption.flatMap(_.getAttributeStatements.headOption.map(_.getAttributes))
      .getOrElse(new java.util.ArrayList[Attribute]())

    val attributeMap = SAMLUtil.extractAttributes(attributes)
    attributeMap should contain("xxx" -> "yyy")
    attributeMap should contain("aaa" -> "bbb")
  }


  def normalize(pem : String ) : String = {
      pem.replaceAll("-----.*-----", "").replaceAll(" ", "").split('\n').map(_.trim.filter(_ >= ' ')).mkString.trim
  }


}
