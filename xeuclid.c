#include <stdio.h> 
#include <openssl/bn.h>

void printBN(char *msg, BIGNUM *a){
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

BIGNUM *resST(BIGNUM *x1, BIGNUM *x2, BIGNUM *q){
	
	BN_CTX *ctx = BN_CTX_new();
	
	BIGNUM *mulRes = BN_new();
	BIGNUM *subRes = BN_new();

	/* mulRes = q * x2 */
	BN_mul(mulRes, q, x2, ctx);

	/* subRes = x1 - mulRes */
	BN_sub(subRes, x1, mulRes);

	return subRes;
}

BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *s = BN_new();
	BIGNUM *s1 = BN_new();
	BIGNUM *s2 = BN_new();
	
	BIGNUM *t = BN_new();
	BIGNUM *t1 = BN_new();
	BIGNUM *t2 = BN_new();

	BIGNUM *r = BN_new();
	BIGNUM *q = BN_new();

	BIGNUM *a_ = BN_new(); // a_copy
	BIGNUM *b_ = BN_new(); // b_copy

	BIGNUM *res = BN_new();

	/* copy */
	BN_copy(a_, a);
	BN_copy(b_, b);

	/* setting s1, s2, t1, t2 */
	BN_dec2bn(&s1, "1");
	BN_dec2bn(&s2, "0");
	BN_dec2bn(&t1, "0");
	BN_dec2bn(&t2, "1");

	while(1){ // if then b_ != 0

		/* r: rem, q: div */
		BN_div(q, r, a_, b_, ctx);

		if(BN_is_zero(b_)){
			BN_copy(x, s1);
			BN_copy(y, t1);

			/* free */
			BN_free(s);
			BN_free(s1);
			BN_free(s2);

			BN_free(t);
			BN_free(t1);
			BN_free(t2);
			
			BN_free(r);
			BN_free(q);

			BN_free(b_);
			BN_free(res);

			return a_;
		}

		/* s */
		s = resST(s1, s2, q);

		/* t */
		t = resST(t1, t2, q);
		
		BN_copy(a_, b_);
		BN_copy(b_, r);
		BN_copy(s1, s2);
		BN_copy(s2, s);
		BN_copy(t1, t2);
		BN_copy(t2, t);
	}
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *b = BN_new();
        BIGNUM *x = BN_new();
        BIGNUM *y = BN_new();
        BIGNUM *gcd;

        if(argc != 3){
                printf("usage: xeuclid num1 num2");
                return -1;
        }

       	BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&b, argv[2]);

        gcd = XEuclid(x,y,a,b);
	
        printBN("(a,b) = ", gcd);
        printBN("a = ", a);
        printBN("b = ", b);
        printBN("x = ", x);
        printBN("y = ", y);
        printf("%s*(%s) + %s*(%s) = %s\n",BN_bn2dec(a),BN_bn2dec(x),BN_bn2dec(b),BN_bn2dec(y),BN_bn2dec(gcd));

        if(a != NULL) BN_free(a);
        if(b != NULL) BN_free(b);
        if(x != NULL) BN_free(x);
        if(y != NULL) BN_free(y);
        if(gcd != NULL) BN_free(gcd);

        return 0;
}

