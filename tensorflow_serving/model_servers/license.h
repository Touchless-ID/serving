#include <stdio.h>
#include <string.h>
# include  <openssl/bio.h>
# include  <openssl/ssl.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tensorflow_serving/model_servers/sysutils.h"

#define AES_256_KEY_SIZE 32

#define AES_BLOCK_SIZE 16

int padding = RSA_PKCS1_PADDING;

char *displaySystemInfo() {
	FILE *fp;
	char UUID[1035];

	/* Open the command for reading. */
	fp = popen("sudo cat /sys/class/dmi/id/product_uuid", "r");
	if (fp == NULL) {
		printf("Failed to run command\n");
		exit(1);
	}

	/* Read the output a line at a time - output it. */
	while (fgets(UUID, sizeof(UUID) - 1, fp) != NULL) {
		//printf("%s", path);
	}

	/* close */
	pclose(fp);
	// printf()
	//system("sudo cat /sys/class/dmi/id/product_uuid");

	printf("UUID : %s ", UUID);
	return UUID;
}

void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	unsigned char *iv, unsigned char *plaintext) {
	EVP_CIPHER_CTX *ctx;

	int len;

	int plaintext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/*
	 * Initialise the decryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits
	 */
	if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
		handleErrors();

	/*
	 * Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary.
	 */
	if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

	/*
	 * Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
		handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;
}

RSA *readPrivate() {

	char *buffer = 0;
	long length;
	FILE *f = fopen("private.pem", "rb");

	if (f) {
		fseek(f, 0, SEEK_END);
		length = ftell(f);
		fseek(f, 0, SEEK_SET);
		buffer = (char *)malloc(length);
		if (buffer) {
			fread(buffer, 1, length, f);
		}
		fclose(f);
	}

	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(buffer, -1);
	if (keybio == NULL) {
		printf("Failed to create key BIO");
		return 0;
	}
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	if (rsa == NULL) {
		printf("Failed to create RSA");
	}

	return rsa;
}

int private_decrypt(unsigned char *enc_data, int data_len, unsigned char *decrypted) {
	RSA *rsa = readPrivate();
	int result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

int Base64Encode(const unsigned char *buffer, size_t length, char **b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);

	*b64text = (*bufferPtr).data;

	return (0); //success
}

bool generate_key(char **b64text) {
	int ret = 0;
	RSA *r = NULL;
	BIGNUM *bne = NULL;
	BIO *bp_public = NULL, *bp_private = NULL;

	int bits = 2048;
	unsigned long e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1) {
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1) {
		goto free_all;
	}

	// 2. save public key
	bp_public = BIO_new_file("public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	//    PEM_write_X509(stdout, r);

	if (ret != 1) {
		goto free_all;
	}



	// 3. save private key
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

	return (ret == 1);
}


/* silly test data to POST */
static const char data[] = "{\"publicKey\":\"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qrio96dQ2AsLNvUOuQa5v+TP\\/mkmWxbC8JEpCfiQOFZeVcufjLbZxRwaoW3+Vua22OfNegSRLa1SQWRGBJENO\\/Q1eeMb+CDRC3DSku1NEktFNi1Wm2XFmb8pb8EDea2Z63WZFlyO8An32tUwzUG60zdSs5kcMVId\\/6Gtkn9FI9TgLcR1akM7EJ8Nv8Uuz4NTs7Er8w95WcwcaqsDSYIRiC06qfpvTCSF7cw+bGQa1455sRXVC4cjYftnSWCaYa9w6XrFdNsowWhETPCdHe0cZ\\/Jj6DK4zvm0mwsSIk+28n6FO6bI8JhGJLDhFEgcYRG6DEXi7+Ei4z9mOtkdqF\\/8wIDAQAB\",\"licenseAction\":\"LVERIFY\",\"hash\":\"7751F8779A5D69C34902828DC1B0848269934131\",\"data\":\"f3268b9508528889010132bf1d55b933d6b420d5eb18486b14f7b595967855ff\",\"uniqueId\":\"6a36aa0e4e5c04ed\",\"timestamp\":\"1556086440\",\"license\":\"QUVTAgAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVycIVZBc0pZwj1EzDF\\/srI6fYeYTuQSk5sbtkL0tRWxc6xqGxjjKKnagQLzlaV5hIUmtpUo3+a5UYdavm8hfiIDNRlTEqEKLUwR\\/9YnhhqY3Asbq5EkofSYgDTwdTKy\\/EWcqJBlQdw07VdIZ8XtUCA4PhdhZPT+ZggNdMxSYQ9q6OULLM4vut9P4bziOb8Crb\",\"bundleId\":\"com.identy.demo\",\"mobileManufacturer\":\"samsung\",\"sdkVersion\":\"1.0.0.1\",\"mobileModel\":\"SM-E500H\",\"licenseFor\":\"face\",\"osVersion\":\"22\",\"snetNonce\":\"w�!x�,�ۼ~F�[\tS�\",\"snetResponse\":\"eyJhbGciOiJSUzI1NiIsIng1YyI6WyJNSUlGa2pDQ0JIcWdBd0lCQWdJUVJYcm9OMFpPZFJrQkFBQUFBQVB1bnpBTkJna3Foa2lHOXcwQkFRc0ZBREJDTVFzd0NRWURWUVFHRXdKVlV6RWVNQndHQTFVRUNoTVZSMjl2WjJ4bElGUnlkWE4wSUZObGNuWnBZMlZ6TVJNd0VRWURWUVFERXdwSFZGTWdRMEVnTVU4eE1CNFhEVEU0TVRBeE1EQTNNVGswTlZvWERURTVNVEF3T1RBM01UazBOVm93YkRFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ1RDa05oYkdsbWIzSnVhV0V4RmpBVUJnTlZCQWNURFUxdmRXNTBZV2x1SUZacFpYY3hFekFSQmdOVkJBb1RDa2R2YjJkc1pTQk1URU14R3pBWkJnTlZCQU1URW1GMGRHVnpkQzVoYm1SeWIybGtMbU52YlRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTmpYa3owZUsxU0U0bSsvRzV3T28rWEdTRUNycWRuODhzQ3BSN2ZzMTRmSzBSaDNaQ1laTEZIcUJrNkFtWlZ3Mks5RkcwTzlyUlBlUURJVlJ5RTMwUXVuUzl1Z0hDNGVnOW92dk9tK1FkWjJwOTNYaHp1blFFaFVXWEN4QURJRUdKSzNTMmFBZnplOTlQTFMyOWhMY1F1WVhIRGFDN09acU5ub3NpT0dpZnM4djFqaTZIL3hobHRDWmUybEorN0d1dHpleEtweHZwRS90WlNmYlk5MDVxU2xCaDlmcGowMTVjam5RRmtVc0FVd21LVkFVdWVVejR0S2NGSzRwZXZOTGF4RUFsK09raWxNdElZRGFjRDVuZWw0eEppeXM0MTNoYWdxVzBXaGg1RlAzOWhHazlFL0J3UVRqYXpTeEdkdlgwbTZ4RlloaC8yVk15WmpUNEt6UEpFQ0F3RUFBYU9DQWxnd2dnSlVNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBVEFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUXFCUXdHV29KQmExb1RLcXVwbzRXNnhUNmoyREFmQmdOVkhTTUVHREFXZ0JTWTBmaHVFT3ZQbSt4Z254aVFHNkRyZlFuOUt6QmtCZ2dyQmdFRkJRY0JBUVJZTUZZd0p3WUlLd1lCQlFVSE1BR0dHMmgwZEhBNkx5OXZZM053TG5CcmFTNW5iMjluTDJkMGN6RnZNVEFyQmdnckJnRUZCUWN3QW9ZZmFIUjBjRG92TDNCcmFTNW5iMjluTDJkemNqSXZSMVJUTVU4eExtTnlkREFkQmdOVkhSRUVGakFVZ2hKaGRIUmxjM1F1WVc1a2NtOXBaQzVqYjIwd0lRWURWUjBnQkJvd0dEQUlCZ1puZ1F3QkFnSXdEQVlLS3dZQkJBSFdlUUlGQXpBdkJnTlZIUjhFS0RBbU1DU2dJcUFnaGg1b2RIUndPaTh2WTNKc0xuQnJhUzVuYjI5bkwwZFVVekZQTVM1amNtd3dnZ0VFQmdvckJnRUVBZFo1QWdRQ0JJSDFCSUh5QVBBQWR3Q2t1UW1RdEJoWUZJZTdFNkxNWjNBS1BEV1lCUGtiMzdqamQ4ME95QTNjRUFBQUFXWmREM1BMQUFBRUF3QklNRVlDSVFDU1pDV2VMSnZzaVZXNkNnK2dqLzl3WVRKUnp1NEhpcWU0ZVk0Yy9teXpqZ0loQUxTYmkvVGh6Y3pxdGlqM2RrM3ZiTGNJVzNMbDJCMG83NUdRZGhNaWdiQmdBSFVBVmhRR21pL1h3dXpUOWVHOVJMSSt4MFoydWJ5WkVWekE3NVNZVmRhSjBOMEFBQUZtWFE5ejVBQUFCQU1BUmpCRUFpQmNDd0E5ajdOVEdYUDI3OHo0aHIvdUNIaUFGTHlvQ3EySzAreUxSd0pVYmdJZ2Y4Z0hqdnB3Mm1CMUVTanEyT2YzQTBBRUF3Q2tuQ2FFS0ZVeVo3Zi9RdEl3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUk5blRmUktJV2d0bFdsM3dCTDU1RVRWNmthenNwaFcxeUFjNUR1bTZYTzQxa1p6d0o2MXdKbWRSUlQvVXNDSXkxS0V0MmMwRWpnbG5KQ0YyZWF3Y0VXbExRWTJYUEx5RmprV1FOYlNoQjFpNFcyTlJHelBodDNtMWI0OWhic3R1WE02dFg1Q3lFSG5UaDhCb200L1dsRmloemhnbjgxRGxkb2d6L0syVXdNNlM2Q0IvU0V4a2lWZnYremJKMHJqdmc5NEFsZGpVZlV3a0k5Vk5NakVQNWU4eWRCM29MbDZnbHBDZUY1ZGdmU1g0VTl4MzVvai9JSWQzVUUvZFBwYi9xZ0d2c2tmZGV6dG1VdGUvS1Ntcml3Y2dVV1dlWGZUYkkzenNpa3daYmtwbVJZS21qUG1odjRybGl6R0NHdDhQbjhwcThNMktEZi9QM2tWb3QzZTE4UT0iLCJNSUlFU2pDQ0F6S2dBd0lCQWdJTkFlTzBtcUdOaXFtQkpXbFF1REFOQmdrcWhraUc5dzBCQVFzRkFEQk1NU0F3SGdZRFZRUUxFeGRIYkc5aVlXeFRhV2R1SUZKdmIzUWdRMEVnTFNCU01qRVRNQkVHQTFVRUNoTUtSMnh2WW1Gc1UybG5iakVUTUJFR0ExVUVBeE1LUjJ4dlltRnNVMmxuYmpBZUZ3MHhOekEyTVRVd01EQXdOREphRncweU1URXlNVFV3TURBd05ESmFNRUl4\"}";

struct WriteThis {
	const char *readptr;
	size_t sizeleft;
};

static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp) {
	struct WriteThis *wt = (struct WriteThis *) userp;
	size_t buffer_size = size * nmemb;

	if (wt->sizeleft) {
		/* copy as much as possible from the source to the destination */
		size_t copy_this_much = wt->sizeleft;
		if (copy_this_much > buffer_size)
			copy_this_much = buffer_size;
		memcpy(dest, wt->readptr, copy_this_much);

		wt->readptr += copy_this_much;
		wt->sizeleft -= copy_this_much;
		return copy_this_much; /* we copied this many bytes */
	}

	return 0; /* no more data left to deliver */
}

int makeRequestAndSave(char path[]) {
	//printf("make request and save \n");
	system(("rm data.data"));

	FILE *fp = fopen("public.pem", "r");
	if (!fp) {
		fprintf(stderr, "unable to open: %s\n", "public.pem");
		return EXIT_FAILURE;
	}
	//printf("make request and save . \n");
	struct stat st = { 0 };

	if (stat(path, &st) == -1) {
		mkdir(path, 0700);
	}
	char folderPath[1000] = "ff";

	strcpy(folderPath, path);

	strcat(folderPath, "/1");
	if (stat(folderPath, &st) == -1) {
		mkdir(folderPath, 0700);
	}

	CURL *curl;
	CURLcode res;

	struct curl_httppost *formpost = NULL;
	struct curl_httppost *lastptr = NULL;
	struct curl_slist *headerlist = NULL;
	static const char buf[] = "Expect:";

	curl_global_init(CURL_GLOBAL_ALL);

	/* Fill in the file upload field */
	curl_formadd(&formpost,
		&lastptr,
		CURLFORM_COPYNAME, "file",
		CURLFORM_FILE, "public.pem",
		CURLFORM_END);

	curl_formadd(&formpost,
		&lastptr,
		CURLFORM_COPYNAME, "license",
		CURLFORM_FILE, "/data/license.lic",
		CURLFORM_END);

	/* Fill in the submit field too, even if this is rarely needed */
	curl_formadd(&formpost,
		&lastptr,
		CURLFORM_COPYNAME, "by",
		CURLFORM_COPYCONTENTS, "identy",
		CURLFORM_END);

	FILE *f1;
	char UUID[1035];

	/* Open the command for reading. */
	f1 = popen("cat /sys/class/dmi/id/product_uuid", "r");
	if (f1 == NULL) {
		printf("Failed to run command\n");
		exit(1);
	}

	/* Read the output a line at a time - output it. */
	while (fgets(UUID, sizeof(UUID) - 1, f1) != NULL) {
		//printf("%s", path);
	}

	/* close */
	pclose(f1);

	curl_formadd(&formpost,
		&lastptr,
		CURLFORM_COPYNAME, "UUID",
		CURLFORM_COPYCONTENTS, UUID,
		CURLFORM_END);



	curl = curl_easy_init();
	/* initalize custom header list (stating that Expect: 100-continue is not
	   wanted */
	headerlist = curl_slist_append(headerlist, buf);
	printf("make request and save .. \n");
	printf("make request and save .. \n");
	char *version = getenv("VERSION");
	if (curl) {
		
		char url[1000] = "https://licensemgr.identy.io/";
		strcat(url, path);
		strcat(url, "/");
		strcat(url, version);
		printf("Loading ... %s \n", url);

		/* what URL that receives this POST */
		curl_easy_setopt(curl, CURLOPT_URL, url);

		curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

		FILE *file = fopen("data.data", "w");

		curl_easy_setopt(curl, CURLOPT_WRITEDATA, file);
		/* Perform the request, res will get the return code */
		res = curl_easy_perform(curl);
		/* Check for errors */
		if (res != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed: %s\n",
				curl_easy_strerror(res));

		/* always cleanup */
		curl_easy_cleanup(curl);

		/* then cleanup the formpost chain */
		curl_formfree(formpost);
		/* free slist */
		curl_slist_free_all(headerlist);
		fclose(file);
	}

	printf("make request and save ... \n");

	char *buffer = 0;
	char *body = 0;

	long length;
	FILE *f = fopen("data.data", "rb");

	if (f) {
		fseek(f, 0, SEEK_END);
		length = ftell(f);
		printf(" Length =%d\n", length);
		fseek(f, 0, SEEK_SET);
		buffer = (char *)malloc(256);

		if (buffer) {
			fread(buffer, 1, 256, f);
		}

		body = (char *)malloc(length);
		if (body) {
			fread(body, 1, length, f);
		}
		//        folderPath = "saved_model.pb";
		strcat(folderPath, "/saved_model.pb");

		//        printf("path =%s\n", folderPath);

		FILE *dataFile = fopen("saved_model.pb.enc", "wb");
		fseek(dataFile, 0, SEEK_SET);

		fwrite(body, length - 256, 1, dataFile);

		fclose(dataFile);

		unsigned char *decryptedkey = (unsigned char *)calloc(4098, sizeof(unsigned char));

		int decrypted_length = private_decrypt(reinterpret_cast<unsigned char *>(buffer), 256,
			reinterpret_cast<unsigned char *>(decryptedkey));
		if (decrypted_length == -1) {
			printf("Unable to load %s \n", path);

			printf("reason %s \n", std::string(reinterpret_cast<const char *>(buffer)).c_str());
			return 0;
		}

		//printf("Decrypted Text =%s\n", decryptedkey);
		printf(" Length ?%d\n", decrypted_length);
		std::string sdecryptedkey(reinterpret_cast<char *>(decryptedkey));
		std::string sfolderPath(reinterpret_cast<char *>(folderPath));

		runAESCrypt(std::string(reinterpret_cast<const char *>(decryptedkey)), "saved_model.pb", "saved_model.pb.enc");

		system(("cp saved_model.pb " + std::string(reinterpret_cast<const char *>(folderPath))).c_str());
		system(("rm saved_model.pb"));
		system(("rm saved_model.pb.enc"));
	}
	printf("make request and save .... done\n");
	
	return 1;


}

int callRest(void) {
	char *base64EncodeOutput;
	SSL_library_init();
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	generate_key(&base64EncodeOutput);

	char *modality = getenv("MODALITY");
	std::string modality_str(reinterpret_cast<char *>(modality));
	int status = 0;
	int faceStatus = 0;
	int fingerStatus = 0;
	if (modality_str == "FAC") {
		char p1[100] = "face_detect_serving";
		status = makeRequestAndSave(p1);

		faceStatus = status;
		if (status != 0) {
			char p2[100] = "Keypoints_server";
			status = makeRequestAndSave(p2);

			char p3[100] = "Face_encoder_serving";
			status = makeRequestAndSave(p3);

			char p4[100] = "face_as_serving";
			status = makeRequestAndSave(p4);

			char p7[100] = "face_as_eye_serving";
			status = makeRequestAndSave(p7);

			char p8[100] = "face_as_nose_serving";
			status = makeRequestAndSave(p8);

		}
	} else if (modality_str == "FIN") {
		char p5[100] = "finger_as_serving";
		status = makeRequestAndSave(p5);

		fingerStatus = status;
		
		if (status != 0) {
			char p6[100] = "finger_cropper_serving";
			status = makeRequestAndSave(p6);

			char p9[100] = "finger_as_roi_serving";
			status = makeRequestAndSave(p9);

			char p10[100] = "finger_detection_serving";
			status = makeRequestAndSave(p10);
		}
	} else if (modality_str == "OCR"){
		char p1[100] = "netra";
		int status = makeRequestAndSave(p1);

		int ocrStatus = status;

		if (status != 0) {
			char p2[100] = "bio_extraction";
			status = makeRequestAndSave(p2);
			
			char p3[100] = "clean_up";
			status = makeRequestAndSave(p3);
			
			char p4[100] = "ocr_key_point";
			status = makeRequestAndSave(p4);
			
			char p5[100] = "identity_extraction";
			status = makeRequestAndSave(p5);
			
		}
		
		if (ocrStatus == 0 ) {
			printf(" Unable to load. Please contact Identy team");
		}
	}
	else {
		printf(" No modality");
	}

	if (faceStatus == 0 & fingerStatus == 0) {
		printf(" Unable to load. Please contact Identy team");
	}
	return 0;
}


