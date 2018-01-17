using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Threading.Tasks;
using System.Xml;
using SimpleSOAPClient.Handlers;
using SimpleSOAPClient.Helpers;

namespace SimpleSOAPClient.BinarySecurityToken
{
    public static class SoapClientExtensions
    {
        private const string wsuNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";

        private const string x509ValueType =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";

        public static SoapClient WithBinarySecurityTokenHeader(this SoapClient soapClient, X509Certificate2 certificate)
        {
            soapClient.OnHttpRequest((arguments, token) => OnSoapEnvelopeRequest(arguments, certificate));

            return soapClient;
        }

        private static async Task OnSoapEnvelopeRequest(
            OnHttpRequestArguments arguments,
            X509Certificate2 x509Certificate2)
        {
            var xmlString = await arguments.Request.Content.ReadAsStringAsync();

            var document = new XmlDocument();
            document.PreserveWhitespace = true;

            document.LoadXml(xmlString);

            const string soapNs = "http://schemas.xmlsoap.org/soap/envelope/";

            var body = (XmlElement)document.DocumentElement.GetElementsByTagName("Body", soapNs).Item(0);

            var bodyId = "id-" + Guid.NewGuid().ToString("N");

            // Id have to be added twice because SignedXml cannot find element with wsu namespace
            var wsuId = document.CreateAttribute("wsu", "Id", wsuNs);
            wsuId.Value = bodyId;
            body.Attributes.Append(wsuId);

            var id = document.CreateAttribute("Id");
            id.Value = bodyId;
            body.Attributes.Append(id);

            var header = (XmlElement)document.DocumentElement.GetElementsByTagName("Header", soapNs).Item(0);

            Sign(document, bodyId, header, x509Certificate2);

            var textWiter = new StringWriter();
            using (var writer = new XmlTextWriter(textWiter))
            {
                document.WriteTo(writer);
                writer.Flush();
                xmlString = textWiter.ToString();

            }
            arguments.Request.Content = new StringContent(xmlString);

        }

        private static void Sign(XmlDocument document, string bodyId, XmlElement header, X509Certificate2 x509Certificate2)
        {
            const string wsseNs = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

            var security = document.CreateElement("wsse", "Security", wsseNs);

            string binarySecurityTokenId = "X509-" + Guid.NewGuid().ToString("N");

            var binarySecurityToken = CreateBinarySecurityToken(document, wsseNs, binarySecurityTokenId, x509Certificate2);
            security.AppendChild(binarySecurityToken);

            // It should be append before signing
            header.AppendChild(security);

            var signedXml = new SignedXml(document);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SigningKey = x509Certificate2.PrivateKey;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

            var referenceToBody = new Reference("#" + bodyId);
            referenceToBody.DigestMethod = "http://www.w3.org/2000/09/xmldsig#sha1";

            //referenceToBody.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            referenceToBody.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(referenceToBody);

            signedXml.KeyInfo = new KeyInfo();

            var referenceToToken = document.CreateElement("wsse", "Reference", wsseNs);
            var referenceToTokenUri = document.CreateAttribute("URI");
            referenceToTokenUri.Value = "#" + binarySecurityTokenId;
            referenceToToken.Attributes.Append(referenceToTokenUri);

            var valueType = document.CreateAttribute("ValueType");
            valueType.Value = x509ValueType;
            referenceToToken.Attributes.Append(valueType);

            var securityTokenReference = document.CreateElement("wsse", "SecurityTokenReference", wsseNs);
            securityTokenReference.AppendChild(referenceToToken);

            signedXml.KeyInfo.AddClause(new KeyInfoNode(securityTokenReference));

            signedXml.ComputeSignature();

            security.AppendChild(signedXml.GetXml());
        }

        private static XmlElement CreateBinarySecurityToken(XmlDocument document, string wsseNs, string binarySecurityTokenId, X509Certificate2 x509Certificate2)
        {
            var result = document.CreateElement("wsse", "BinarySecurityToken", wsseNs);
            var encoding = document.CreateAttribute("EncodingType");
            encoding.Value =
                "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
            result.Attributes.Append(encoding);

            var valueType = document.CreateAttribute("ValueType");
            valueType.Value = x509ValueType;
            result.Attributes.Append(valueType);

            var idAttribute = document.CreateAttribute("wsu", "Id", wsuNs);
            idAttribute.Value = binarySecurityTokenId;
            result.Attributes.Append(idAttribute);

            result.InnerText = Convert.ToBase64String(x509Certificate2.RawData);

            return result;
        }
    }
}