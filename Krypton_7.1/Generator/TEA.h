//extern "C" unsigned int _fltused=0;

// Constants

#define CVTBUFSIZE		256
#define OUT_PRECISION	6

typedef struct
{
	unsigned int mantissal:32;
	unsigned int mantissah:20;
	unsigned int exponent:11;
	unsigned int sign:1;
} double_t;

// Main code

#define MX (z>>5^y<<2) + (y>>3^z<<4)^(sum^y) + (k[p&3^e]^z)

long block_tea(unsigned long* v,int n,unsigned long* k)
{
	unsigned long z=v[n-1], y=v[0], sum=0, e, DELTA=0x9e3779b9;
	long p, q ;
	if (n > 1) /* Coding Part */
	{
		q = 6+52/n ;
		while (q-- > 0)
		{
			sum += DELTA;
			e = sum >> 2&3 ;
			for (p=0; p<n-1; p++) y = v[p+1], z = v[p] += MX;
			y = v[0];
			z = v[n-1] += MX;
		}
		return 0 ; 
	}
	else if (n < -1) /* Decoding Part */
	{
		n = -n ;
		q = 6+52/n ;
		sum = q*DELTA ;
		while (sum != 0)
		{
			e = sum>>2 & 3;
			for (p=n-1; p>0; p--) z = v[p-1], y = v[p] -= MX;
			z = v[n-1];
			y = v[0] -= MX;
			sum -= DELTA;
		}
		return 0;
	}
	return 1;
}

void xtea_encipher(unsigned int num_rounds, unsigned long* v, unsigned long* k)
{
	unsigned long v0=v[0], v1=v[1], i;
	unsigned long sum=0, delta=0x9E3779B9;
	for(i=0; i<num_rounds; i++)
	{
		v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
		sum += delta;
		v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
	}
	v[0]=v0; v[1]=v1;
}

void xtea_decipher(unsigned int num_rounds, unsigned long* v, unsigned long* k)
{
	unsigned long v0=v[0], v1=v[1], i;
	unsigned long delta=0x9E3779B9, sum=delta*num_rounds;
	for(i=0; i<num_rounds; i++)
	{
		v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
		sum -= delta;
		v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
	}
	v[0]=v0; v[1]=v1;
}

void tea_encrypt(unsigned long* v, unsigned long* k)
{
	unsigned long v0=v[0], v1=v[1], sum=0, i;
	unsigned long delta=0x9e3779b9;
	unsigned long k0=k[0], k1=k[1], k2=k[2], k3=k[3];
	for (i=0; i < 32; i++)
	{
		sum += delta;
		v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
	}
	v[0]=v0; v[1]=v1;
}

void tea_decrypt(unsigned long* v, unsigned long* k)
{
	unsigned long v0=v[0], v1=v[1], sum=0xC6EF3720, i;
	unsigned long delta=0x9e3779b9;
	unsigned long k0=k[0], k1=k[1], k2=k[2], k3=k[3];
	for(i=0; i<32; i++)
	{
		v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
		v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
		sum -= delta;
	}
	v[0]=v0; v[1]=v1;
}

//////////////////////////////////////////////////////////////////////////

char * __stdcall _strncat(char * front,const char * back,int count)
{
	char *start = front;

	while(*front++)
		;
	front--;

	while(count--)
		if(!(*front++ = *back++)) return(start);

	*front = '\0';
	return(start);
}

char * __stdcall _l2a(long value, char *string, int radix)
{
	unsigned long	val;
	int				negative;
	char			buffer[33];
	char			*pos;
	int				digit;

	if(value < 0 && radix == 10)
	{
		negative = 1;
		val = -value;
	}
	else
	{
		negative = 0;
		val = value;
	}

	pos = &buffer[32];
	*pos = '\0';

	do
	{
		digit = val % radix;
		val = val / radix;
		if(digit < 10)
			*--pos = '0' + digit;
		else
			*--pos = 'a' + digit - 10;
	}
	while (val != 0L);

	if(negative)
		*--pos = '-';
	else
		*--pos = '+';

	memcpy(string, pos, &buffer[32] - pos + 1);
	return string;
}

void __stdcall _formatstring(char *string,int decimal,int sign,int expn)
{
	char	buf[64]={0};
	char	buf2[64]={0};
	int		x;

	if(sign != 0)
		lstrcat(buf,"-");

	if(decimal <= 0)
	{
		lstrcat(buf,"0.");
		while(decimal < 0)
		{
			lstrcat(buf,"0");
			decimal++;
		}
		lstrcat(buf,string);
	}
	else
	{
		x=lstrlen(string);
		_strncat(buf,string,decimal);
		if(x != decimal)
		{
			lstrcat(buf,".");
			lstrcat(buf,&string[decimal]);
		}
	}

	x=lstrlen(buf)-1;
	while(x)
	{
		if(buf[x] == '0')
		{
			buf[x]='\0';
			x--;
		}
		else break;
	}

	x=lstrlen(buf)-1;
	if(buf[x] == '.') buf[x]='\0';

	if(expn != NULL)
	{
		_l2a(expn,buf2,10);
		lstrcat(buf,"e");
		lstrcat(buf,buf2);
	}

	lstrcpy(string,buf);
}

int __cdecl _isnan(double __x)
{
	union
	{
		double*   __x;
		double_t*   x;
	} x;
	x.__x = &__x;
	return (x.x->exponent == 0x7ff && (x.x->mantissah != 0 || x.x->mantissal != 0));
}

int __cdecl _isinf(double __x)
{
	union
	{
		double*   __x;
		double_t*   x;
	} x;
	x.__x = &__x;
	return (x.x->exponent == 0x7ff && (x.x->mantissah == 0 && x.x->mantissal == 0));
}

double __cdecl _modf(double x,double *y)
{
	WORD	cw1,cw2;

	_asm
	{
	mov		edi,[y]
	fnstcw	[cw1]
	fwait
	mov		ax,[cw1]
	or		ax,0x0c3f
	mov		[cw2],ax
	fldcw	[cw2]
	fwait
	fld		[x]
	frndint
	fstp	qword ptr [edi]
	fwait
	fld		[x]
	fsub	qword ptr [edi]
	fldcw	[cw1]
	fwait
	}
}

char * __cdecl _cvt(double arg,int ndigits,int *decpt,char *buf)
{
	int		r2;
	double	fi,fj;
	char	*p,*p1;

	if(ndigits < 0) ndigits = 0;
	if(ndigits >= CVTBUFSIZE - 1) ndigits = CVTBUFSIZE - 2;
	r2 = 0;
	p = &buf[0];
	if(arg < 0)
	{
		arg = -arg;
	}
	arg = _modf(arg, &fi);
	p1 = &buf[CVTBUFSIZE];

	if(fi != 0)
	{
		p1 = &buf[CVTBUFSIZE];
		while(fi != 0)
		{
			fj = _modf(fi / 10, &fi);
			*--p1 = (int)((fj + .03) * 10) + '0';
			r2++;
		}
		while(p1 < &buf[CVTBUFSIZE]) *p++ = *p1++;
	}
	else if(arg > 0)
	{
		while((fj = arg * 10) < 1)
		{
			arg = fj;
			r2--;
		}
	}
	p1 = &buf[ndigits];
	p1 += r2;
	*decpt = r2;
	if(p1 < &buf[0])
	{
		buf[0] = '\0';
		return buf;
	}
	while(p <= p1 && p < &buf[CVTBUFSIZE])
	{
		arg *= 10;
		arg = _modf(arg, &fj);
		*p++ = (int) fj + '0';
	}
	if(p1 >= &buf[CVTBUFSIZE])
	{
		buf[CVTBUFSIZE - 1] = '\0';
		return buf;
	}
	p = p1;
	*p1 += 5;
	while(*p1 > '9')
	{
		*p1 = '0';
		if(p1 > buf)
			++*--p1;
		else
		{
			*p1 = '1';
			(*decpt)++;
			if (p > buf) *p = '0';
			p++;
		}
	}
	*p = '\0';
	return buf;
}

bool __cdecl _ftoa(double x,char *string)
{
	int		decimal=0,expn=0,sign;

	if(string)
	{
		if(x == NULL)
		{
			lstrcpy(string,"0");
			return true;
		}
		else if(_isnan(x))
		{
			lstrcpy(string,"nan");
			return true;
		}
		else if(_isinf(x) > 0)
		{
			lstrcpy(string,"+inf");
			return true;
		}
		else if(_isinf(x) < 0)
		{
			lstrcpy(string,"-inf");
			return true;
		}
		else
		{
			if(x < 0)
			{
				x=-x;
				sign=1;
			}
			else
			{
				sign=0;
			}

			/*
			if(x < 0.01)
			{
				while(x < 0.1)
				{
					x *= 10.0;
					expn--;
				}
			}
			else if(x > 9999.9)
			{
				while(x >= 10.0)
				{
					x /= 10.0;
					expn++;
				}
			}
			*/

			_cvt(x,OUT_PRECISION,&decimal,string);
			_formatstring(string,decimal,sign,expn);
		}
		return true;
	}
	return false;
}