/*
* Author: Hyun-min Kim <hmkim@hancom.com>
*/

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <sys/stat.h>

#include <Python.h>
#include <stdlib.h>

#include "grmpycaller.h"

//-----------------------------------------------------------------------
const char *g_cert_path = "/etc/gooroom/agent/server_certificate.crt";
const char *g_signature_path = "/var/tmp/gooroom-agent-service/";

//-----------------------------------------------------------------------
static void decode_base64(
    char *text, unsigned char **decoded_text, size_t *decoded_text_len)
{
    //calc text's length to decode
    size_t text_len = strlen(text);
    size_t padding = 0;

    if (text[text_len-1] == '=' && text[text_len-2] == '=')
        padding = 2;
    else if (text[text_len-1] == '=')
        padding = 1;

    int decoding_text_len = (text_len*3)/4 - padding;

    //decode
    *decoded_text = (unsigned char*)calloc(1, decoding_text_len + 1);
    BIO *bio = BIO_new_mem_buf(text, -1);
    BIO *b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    *decoded_text_len = BIO_read(bio, *decoded_text, strlen(text));

    BIO_free_all(bio);
}

//-----------------------------------------------------------------------
static EVP_PKEY* get_pubkey_from_cert(const char *cert_path) 
{
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    BIO *certbio = BIO_new(BIO_s_file());
    BIO_read_filename(certbio, cert_path);

    EVP_PKEY *pkey = NULL;

    X509 *cert = PEM_read_bio_X509(certbio, NULL, 0, NULL);
    if (!cert) goto ERR_0;

    pkey = X509_get_pubkey(cert);
    if (!pkey)  goto ERR_1;

ERR_1:
    X509_free(cert);
ERR_0:
    BIO_free_all(certbio);

    return pkey;
}

//-----------------------------------------------------------------------
static int _verify_signature(
    const char *cert_path, const char *data, char *signature) 
{
    //make rsa public key
    EVP_PKEY *evp_key = get_pubkey_from_cert(cert_path);
    if (!evp_key) return READ_PUBKEY_FROM_CERT_ERROR;

    //decode signature from base64
    unsigned char *decoded_signature;
    size_t decoded_signature_len;
    decode_base64(signature, &decoded_signature, &decoded_signature_len);

    //verify
    EVP_MD_CTX *evp_ctx = EVP_MD_CTX_create();

    int ret_code = VERIFY_SUCCESS;
    if (EVP_DigestVerifyInit(evp_ctx, NULL, EVP_sha256(),NULL, evp_key)<=0) {
        ret_code = DIGEST_VERIFY_INIT_ERROR;
        goto CLEANUP;
    }
    if (EVP_DigestVerifyUpdate(evp_ctx, data, strlen(data)) <= 0) {
        ret_code = DIGEST_VERIFY_UPDATE_ERROR;
        goto CLEANUP;
    }
    if (EVP_DigestVerifyFinal(evp_ctx, decoded_signature, decoded_signature_len) != 1) {
        ret_code = DIGEST_VERIFY_FINAL_ERROR;
        goto CLEANUP;
    }

CLEANUP:
    EVP_MD_CTX_cleanup(evp_ctx);
    free(decoded_signature);
    EVP_PKEY_free(evp_key);

    return ret_code;
}

//-----------------------------------------------------------------------
static int read_filesize(FILE *fp)
{
    struct stat file_stat;
    fstat(fileno(fp), &file_stat);
    return file_stat.st_size;
}

//-----------------------------------------------------------------------
static const char* split_filename(const char *path)
{
    int len = strlen(path);
    int i;
    for (i=len-1; i >= 0; i--) { 
        if (path[i] == '/') break;
    }
    return path+i+1;
}
   
//-----------------------------------------------------------------------
static void replace_slash_dot(char *path)
{
	int len = strlen(path);
	int i;
	for (i=0; i < len; i++) {
		if (path[i] == '/') path[i] = '.';
	}
}

//-----------------------------------------------------------------------
#define TRIVIAL_LEN 4096
int verify_signature(const char *file_path) 
{
    //read file
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        return FILE_OPEN_ERROR;
    }
    int file_size = read_filesize(fp);
    char *text = (char *)malloc(file_size+1);
    fread(text, 1, file_size, fp);
    text[file_size] = 0;
    fclose(fp);

	//create dirname of signature
	int sig_dir_len = strlen(file_path)+1;
	char *sig_dir = (char *)calloc(1, sig_dir_len);
	snprintf(sig_dir, sig_dir_len, "%s", file_path);
	replace_slash_dot(sig_dir);
	
    //read signature
    char signature_name[TRIVIAL_LEN] = { 0, };
    const char *fn = split_filename(file_path);
    snprintf(signature_name, sizeof(signature_name), 
        "%s%s/%s+signature", g_signature_path, sig_dir, fn);
    fp = fopen(signature_name, "r");
    if (!fp) {
        free(text);
        return FILE_OPEN_ERROR;
    }
    char signature[TRIVIAL_LEN] = { 0, };
    fread(signature, 1, sizeof(signature), fp);
    fclose(fp);

    //do
    int ret_code = _verify_signature(g_cert_path, text, signature);
    free(text);
    return ret_code; 
}

//-----------------------------------------------------------------------
char*
do_task(const char *task)
{
    PyObject *module_name, *module, *func, *args, *value;
	char *char_value, *return_value = NULL;
	Py_ssize_t value_size = 0;

    putenv(PYTHONPATH);

    Py_Initialize();

    module_name = PyUnicode_FromString(MODULE_NAME);
    module = PyImport_Import(module_name);
    Py_DECREF(module_name);

	if (module == NULL) goto ERR_MODULE;

	func = PyObject_GetAttrString(module, FUNC_NAME);
	if (!func) goto ERR_FUNCTION;

	args = PyTuple_New(1);
	value = PyUnicode_FromString(task);
	PyTuple_SetItem(args, 0, value);

	value = PyObject_CallObject(func, args);
	Py_DECREF(args);
	if (!value) goto ERR_CALL;

	char_value = PyUnicode_AsUTF8AndSize(value, &value_size);
	return_value = (char *)calloc(1, value_size+1);
	memcpy(return_value, char_value, value_size);

	Py_DECREF(value);

ERR_CALL:
	Py_DECREF(func);
ERR_FUNCTION:
    Py_DECREF(module);
ERR_MODULE:
   	Py_Finalize();

	return return_value;
}
