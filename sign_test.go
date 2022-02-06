package dsig

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
)



func TestSign(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := NewDefaultSigningContext(randomKeyStore)

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}
	id := "_97e34c50-65ec-4132-8b39-02933960a96a"
	authnRequest.CreateAttr("ID", id)
	hash := crypto.SHA256.New()
	canonicalized, err := ctx.Canonicalizer.Canonicalize(authnRequest)
	require.NoError(t, err)

	_, err = hash.Write(canonicalized)
	require.NoError(t, err)
	digest := hash.Sum(nil)

	signed, err := ctx.SignEnveloped(authnRequest)
	require.NoError(t, err)
	require.NotEmpty(t, signed)

	sig := signed.FindElement("//" + SignatureTag)
	require.NotEmpty(t, sig)

	signedInfo := sig.FindElement("//" + SignedInfoTag)
	require.NotEmpty(t, signedInfo)

	canonicalizationMethodElement := signedInfo.FindElement("//" + CanonicalizationMethodTag)
	require.NotEmpty(t, canonicalizationMethodElement)

	canonicalizationMethodAttr := canonicalizationMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, canonicalizationMethodAttr)
	require.Equal(t, CanonicalXML11AlgorithmId.String(), canonicalizationMethodAttr.Value)

	signatureMethodElement := signedInfo.FindElement("//" + SignatureMethodTag)
	require.NotEmpty(t, signatureMethodElement)

	signatureMethodAttr := signatureMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, signatureMethodAttr)
	require.Equal(t, "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", signatureMethodAttr.Value)

	referenceElement := signedInfo.FindElement("//" + ReferenceTag)
	require.NotEmpty(t, referenceElement)

	idAttr := referenceElement.SelectAttr(URIAttr)
	require.NotEmpty(t, idAttr)
	require.Equal(t, "#"+id, idAttr.Value)

	transformsElement := referenceElement.FindElement("//" + TransformsTag)
	require.NotEmpty(t, transformsElement)

	transformElement := transformsElement.FindElement("//" + TransformTag)
	require.NotEmpty(t, transformElement)

	algorithmAttr := transformElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, algorithmAttr)
	require.Equal(t, EnvelopedSignatureAltorithmId.String(), algorithmAttr.Value)

	digestMethodElement := referenceElement.FindElement("//" + DigestMethodTag)
	require.NotEmpty(t, digestMethodElement)

	digestMethodAttr := digestMethodElement.SelectAttr(AlgorithmAttr)
	require.NotEmpty(t, digestMethodElement)
	require.Equal(t, "http://www.w3.org/2001/04/xmlenc#sha256", digestMethodAttr.Value)

	digestValueElement := referenceElement.FindElement("//" + DigestValueTag)
	require.NotEmpty(t, digestValueElement)
	require.Equal(t, base64.StdEncoding.EncodeToString(digest), digestValueElement.Text())
}

func TestSignErrors(t *testing.T) {
	randomKeyStore := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:        crypto.SHA512_256,
		KeyStore:    randomKeyStore,
		IdAttribute: DefaultIdAttr,
		Prefix:      DefaultPrefix,
	}

	authnRequest := &etree.Element{
		Space: "samlp",
		Tag:   "AuthnRequest",
	}

	_, err := ctx.SignEnveloped(authnRequest)
	require.Error(t, err)
}

func TestSignNonDefaultID(t *testing.T) {
	// Sign a document by referencing a non-default ID attribute ("OtherID"),
	// and confirm that the signature correctly references it.
	ks := RandomKeyStoreForTest()
	ctx := &SigningContext{
		Hash:          crypto.SHA256,
		KeyStore:      ks,
		IdAttribute:   "OtherID",
		Prefix:        DefaultPrefix,
		Canonicalizer: MakeC14N11Canonicalizer(),
	}

	signable := &etree.Element{
		Space: "foo",
		Tag:   "Bar",
	}

	id := "_97e34c50-65ec-4132-8b39-02933960a96b"

	signable.CreateAttr("OtherID", id)
	signed, err := ctx.SignEnveloped(signable)
	require.NoError(t, err)

	ref := signed.FindElement("./Signature/SignedInfo/Reference")
	require.NotNil(t, ref)
	refURI := ref.SelectAttrValue("URI", "")
	require.Equal(t, refURI, "#"+id)
}

func getDateTime() string {

	current_time := time.Now()

	formatted := fmt.Sprintf ("%d-%02d-%02dT%02d:%02d:%02d+05:30\n",
		current_time.Year(), current_time.Month(), current_time.Day(),
		current_time.Hour(), current_time.Minute(), current_time.Second())
	return formatted
}

func getJjulian() string {

	current_time := time.Now()

	formatted := fmt.Sprintf ("%d-%02d-%02dT%02d:%02d:%02d+05:30\n",
		current_time.Year(), current_time.Month(), current_time.Day(),
		current_time.Hour(), current_time.Minute(), current_time.Second())
	return formatted
}



func TestSign_RSAKeyValue(t *testing.T) {

	fmt.Println("Current time",getDateTime())
	tryout := `<?xml version="1.0" encoding="UTF-8"?><ns2:ReqDiagnostic xmlns:ns2="http://bbps.org/schema"><Head origInst="FE41" refId="n8tsUgAINn71teBaQVYPwWa6Ujw20341832" ts="2022-02-03T18:32:30+05:30" ver="1.0"/></ns2:ReqDiagnostic>`

	doc := etree.NewDocument()
	err := doc.ReadFromBytes([]byte(tryout))
	if err != nil {
		panic(err)
	}

	pkeyBytes, err := ioutil.ReadFile("/Users/vu3mmg/work/2wayssl/certs/private_key.der")
	if err != nil {
		panic(err)
	}

	certBytes, err := ioutil.ReadFile("/Users/vu3mmg/work/2wayssl/certs/digiledge_signer.crt")
	block, _ := pem.Decode(certBytes)
	certBytes = block.Bytes
	_, err = x509.ParseCertificate(certBytes)
	if err != nil {
		panic(err)
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(pkeyBytes)
	if err != nil {
		panic(err)
	}

	storeForTest := &MemoryX509KeyStore{}
	storeForTest.SetKeyPair(privateKey.( *rsa.PrivateKey), certBytes)
	ctx := NewDefaultSigningContext(storeForTest)
	ctx.Canonicalizer = MakeC14N10RecCanonicalizer()
	ctx.Prefix = ""
	ctx.KeyInfoType = RSAKeyInfo
	signedElement, err := ctx.SignEnveloped(doc.Root())
	require.NoError(t, err)

	element := signedElement.FindElement("//Signature/SignatureValue")
	require.NotEmpty(t, element)

	element = signedElement.FindElement("//Signature/KeyInfo/KeyValue/RSAKeyValue/Modulus")
	require.NotEmpty(t, element)

	element = signedElement.FindElement("//Signature/KeyInfo/KeyValue/RSAKeyValue/Exponent")
	require.NotEmpty(t, element)

	fmt.Printf("all test")
	doc = etree.NewDocument()
	doc.SetRoot(signedElement)
	signedXml, err := doc.WriteToString()
	if err != nil {
		panic(err)
	}

	fmt.Println("Signed XML -----------------")
	fmt.Println(signedXml)
	fmt.Println("Signed XML -----------------")
	//
	//	//ioutil.WriteFile("signed_xml.txt", []byte(signedXml), 777)
	//	//
	//	//signedBytes, err := ioutil.ReadFile("signed_xml.txt")
	//	//if err != nil {
	//	//	panic(err)
	//	//}
	//

	body := signedXml

	client := &http.Client{}
	// build a new request, but not doing the POST yet
	req, err := http.NewRequest("POST", "http://localhost:9084/", bytes.NewBuffer([]byte(body)))
	if err != nil {
		fmt.Println(err)
	}
	// you can then set the Header here
	// I think the content-type should be "application/xml" like json...
	req.Header.Add("Content-Type", "application/xml; charset=utf-8")
	// now POST it
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(resp)
}

