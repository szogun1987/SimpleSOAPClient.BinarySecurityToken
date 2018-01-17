# Extension to SimpleSOAPClient that allows BinarySecurityToken authorization

*Disclaimer*
This package is not fully functional yet. It not configurabe, It's API may change. For now it just works for me.

## Usage
```
var certificatePath = "PATH_TO_PFX_OR_P12_FILE";
var certificateData = File.ReadAllBytes(certificatePath);
var certificate = new X509Certificate2(certificateData, "password");
using (var client = SoapClient.Prepare())
{
	client.WithBinarySecurityTokenHeader(certificate);

	var envelope = SoapEnvelope
		.Prepare()
		.Body(new SampleRequest());

	var soapResponse = await client.SendAsync("https://some-server.org", "action", )
}
```