package token

import (
	"crypto/rsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/api/core/v1"
	"k8s.io/client-go/rest"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"github.com/golang/glog"
)

const (
	curveName = "P-256"    // curveName is the name of the RSA curve
)

var curveEll = elliptic.P256()

// AuthToken contains information about the authenticated user
type AuthToken struct {
	Username   	string
	Exp 		time.Time		`json:"exp"`
	Groups 		[]string
	Assertions 	map[string]string
}

const (
	serviceAccountNamespaceFile = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// GenerateKeypair generates a public and private RSA key, to be
// used for signing and verifying authentication tokens.
func GenerateKeypair(filename string) (err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return
	}
	keyPEM := x509.MarshalPKCS1PrivateKey(priv)
	pub := priv.Public()
	pubKeyPEM, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("Error marshalling public key: %v", err)
	}

	// try to write generated keys to K8S in cluster secret
	err = writeSigningSecret(keyPEM,pubKeyPEM)
	// if seret write returns error whe are not using a secret
	// so just write the generated data to the key files
	if err == nil {
		glog.Info("Running in kubernetes cluster")
		// if secret was ceated sucessfully or was already existing
		// we read the secret to use keypair in the secret if it was already present
		glog.Info("Reading stored secret")
		secret,err := readSigningSecret()
		if err != nil {
			glog.Fatal("error reading secret")
		}
		// now we write the content of the secert to the files
		keyPEM = secret.Data["signing.priv"]
		pubKeyPEM = secret.Data["signing.pub"]

	}

	glog.Info("Storing keypair in local files")
	err = ioutil.WriteFile(filename+".priv", keyPEM, os.FileMode(0600))
	err = ioutil.WriteFile(filename+".pub", pubKeyPEM, os.FileMode(0644))

	return
}

// kubernets secret handling

func writeSigningSecret(privKey, pubKey []byte) error {
	// check if running in cluster, if not return error
	if _,err := rest.InClusterConfig(); err != nil {
		return err
	}

	newSecret := v1.Secret{
		Type:v1.SecretTypeOpaque,
		ObjectMeta: metav1.ObjectMeta{Name: getSecretName()},
		Data: map[string][]byte{"signing.priv": privKey, "signing.pub": pubKey},
	}

	_ , err := getK8sClient().CoreV1().Secrets(getNamespace()).Create(&newSecret)

	// only fail if error wasn't due to already existing secret
	if err != nil && !k8serrors.IsAlreadyExists(err){
		return err
	}
	return nil
}

func readSigningSecret() (*v1.Secret, error) {
	secret, err := getK8sClient().CoreV1().Secrets(getNamespace()).Get(getSecretName(), metav1.GetOptions{})
	if err != nil{
		return nil, err
	}

	return secret, nil
}

func getNamespace() (ns string) {
	ns = "default"
	if  os.Getenv("MY_NAMESPACE") != "" {
		ns = os.Getenv("MY_NAMESPACE")
	}
	if _,err := os.Stat(serviceAccountNamespaceFile); err == nil {
		namespace,err := ioutil.ReadFile(serviceAccountNamespaceFile)
		if err != nil {
			glog.Errorf("Error reading serviceaccount namespace: %v",err)
			ns = string(namespace)
		}
	}
	glog.Infof("Running in K8S namespace: %s",ns)
	return
}

func getSecretName() string {
	ns := "ldap-signing-cert-secret"
	if os.Getenv("SIGNING_CERT_SECRET_NAME") != ""{
		ns = os.Getenv("SIGNING_CERT_SECRET_NAME")
	}
	return ns
}

func getK8sClient() *kubernetes.Clientset {
	// creates the in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		glog.Fatal(err)
	}

	// creates the clientset
	clientset, err := kubernetes.NewForConfig(config)

	if err != nil {
		glog.Fatal(err)
	}
	return clientset
}