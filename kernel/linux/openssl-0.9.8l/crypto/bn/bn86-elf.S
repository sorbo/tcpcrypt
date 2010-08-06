





	.file	"bn-586.s"
.text
.globl	bn_mul_add_words
.type	bn_mul_add_words,@function
.align	16
bn_mul_add_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	xorl	%esi,		%esi
	movl	20(%esp),	%edi
	movl	28(%esp),	%ecx
	movl	24(%esp),	%ebx
	andl	$4294967288,	%ecx
	movl	32(%esp),	%ebp
	pushl	%ecx
	jz	.L000maw_finish
	movd	%ebp,		%mm0
	pxor	%mm1,		%mm1
.L002maw_sse2_loop:
	movd	(%edi),		%mm3
	paddq	%mm3,		%mm1
	movd	(%ebx),		%mm2
	pmuludq	%mm0,		%mm2
	movd	4(%ebx),	%mm4
	pmuludq	%mm0,		%mm4
	movd	8(%ebx),	%mm6
	pmuludq	%mm0,		%mm6
	movd	12(%ebx),	%mm7
	pmuludq	%mm0,		%mm7
	paddq	%mm2,		%mm1
	movd	4(%edi),	%mm3
	paddq	%mm4,		%mm3
	movd	8(%edi),	%mm5
	paddq	%mm6,		%mm5
	movd	12(%edi),	%mm4
	paddq	%mm4,		%mm7
	movd	%mm1,		(%edi)
	movd	16(%ebx),	%mm2
	pmuludq	%mm0,		%mm2
	psrlq	$32,		%mm1
	movd	20(%ebx),	%mm4
	pmuludq	%mm0,		%mm4
	paddq	%mm3,		%mm1
	movd	24(%ebx),	%mm6
	pmuludq	%mm0,		%mm6
	movd	%mm1,		4(%edi)
	psrlq	$32,		%mm1
	movd	28(%ebx),	%mm3
	addl	$32,		%ebx
	pmuludq	%mm0,		%mm3
	paddq	%mm5,		%mm1
	movd	16(%edi),	%mm5
	paddq	%mm5,		%mm2
	movd	%mm1,		8(%edi)
	psrlq	$32,		%mm1
	paddq	%mm7,		%mm1
	movd	20(%edi),	%mm5
	paddq	%mm5,		%mm4
	movd	%mm1,		12(%edi)
	psrlq	$32,		%mm1
	paddq	%mm2,		%mm1
	movd	24(%edi),	%mm5
	paddq	%mm5,		%mm6
	movd	%mm1,		16(%edi)
	psrlq	$32,		%mm1
	paddq	%mm4,		%mm1
	movd	28(%edi),	%mm5
	paddq	%mm5,		%mm3
	movd	%mm1,		20(%edi)
	psrlq	$32,		%mm1
	paddq	%mm6,		%mm1
	movd	%mm1,		24(%edi)
	psrlq	$32,		%mm1
	paddq	%mm3,		%mm1
	movd	%mm1,		28(%edi)
	addl	$32,		%edi
	psrlq	$32,		%mm1
	subl	$8,		%ecx
	jnz	.L002maw_sse2_loop
	movd	%mm1,		%esi
	emms
	jmp	.L000maw_finish
.L001maw_loop:
	movl	%ecx,		(%esp)

	movl	(%ebx),		%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	(%edi),		%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		(%edi)
	movl	%edx,		%esi

	movl	4(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	4(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		4(%edi)
	movl	%edx,		%esi

	movl	8(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	8(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		8(%edi)
	movl	%edx,		%esi

	movl	12(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	12(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		12(%edi)
	movl	%edx,		%esi

	movl	16(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	16(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		16(%edi)
	movl	%edx,		%esi

	movl	20(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	20(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		20(%edi)
	movl	%edx,		%esi

	movl	24(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	24(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		24(%edi)
	movl	%edx,		%esi

	movl	28(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	28(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		28(%edi)
	movl	%edx,		%esi

	movl	(%esp),		%ecx
	addl	$32,		%ebx
	addl	$32,		%edi
	subl	$8,		%ecx
	jnz	.L001maw_loop
.L000maw_finish:
	movl	32(%esp),	%ecx
	andl	$7,		%ecx
	jnz	.L003maw_finish2
	jmp	.L004maw_end
.align 16
.L003maw_finish2:

	movl	(%ebx),		%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	(%edi),		%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	4(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	4(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		4(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	8(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	8(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		8(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	12(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	12(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		12(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	16(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	16(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		16(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	20(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	20(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	decl	%ecx
	movl	%eax,		20(%edi)
	movl	%edx,		%esi
	jz	.L004maw_end

	movl	24(%ebx),	%eax
	mull	%ebp
	addl	%esi,		%eax
	movl	24(%edi),	%esi
	adcl	$0,		%edx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		24(%edi)
	movl	%edx,		%esi
.L004maw_end:
	movl	%esi,		%eax
	popl	%ecx
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_mul_add_words_end:
.size	bn_mul_add_words,.L_bn_mul_add_words_end-bn_mul_add_words
.ident	"bn_mul_add_words"
.text
.globl	bn_mul_words
.type	bn_mul_words,@function
.align	16
bn_mul_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	xorl	%esi,		%esi
	movl	20(%esp),	%edi
	movl	24(%esp),	%ebx
	movl	28(%esp),	%ebp
	movl	32(%esp),	%ecx
	andl	$4294967288,	%ebp
	jz	.L005mw_finish
.L006mw_loop:

	movl	(%ebx),		%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		(%edi)
	movl	%edx,		%esi

	movl	4(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		4(%edi)
	movl	%edx,		%esi

	movl	8(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		8(%edi)
	movl	%edx,		%esi

	movl	12(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		12(%edi)
	movl	%edx,		%esi

	movl	16(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		16(%edi)
	movl	%edx,		%esi

	movl	20(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		20(%edi)
	movl	%edx,		%esi

	movl	24(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		24(%edi)
	movl	%edx,		%esi

	movl	28(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		28(%edi)
	movl	%edx,		%esi

	addl	$32,		%ebx
	addl	$32,		%edi
	subl	$8,		%ebp
	jz	.L005mw_finish
	jmp	.L006mw_loop
.L005mw_finish:
	movl	28(%esp),	%ebp
	andl	$7,		%ebp
	jnz	.L007mw_finish2
	jmp	.L008mw_end
.align 16
.L007mw_finish2:

	movl	(%ebx),		%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	4(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		4(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	8(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		8(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	12(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		12(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	16(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		16(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	20(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		20(%edi)
	movl	%edx,		%esi
	decl	%ebp
	jz	.L008mw_end

	movl	24(%ebx),	%eax
	mull	%ecx
	addl	%esi,		%eax
	adcl	$0,		%edx
	movl	%eax,		24(%edi)
	movl	%edx,		%esi
.L008mw_end:
	movl	%esi,		%eax
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_mul_words_end:
.size	bn_mul_words,.L_bn_mul_words_end-bn_mul_words
.ident	"bn_mul_words"
.text
.globl	bn_sqr_words
.type	bn_sqr_words,@function
.align	16
bn_sqr_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	movl	20(%esp),	%esi
	movl	24(%esp),	%edi
	movl	28(%esp),	%ebx
	andl	$4294967288,	%ebx
	jz	.L009sw_finish
.L010sw_loop:

	movl	(%edi),		%eax
	mull	%eax
	movl	%eax,		(%esi)
	movl	%edx,		4(%esi)

	movl	4(%edi),	%eax
	mull	%eax
	movl	%eax,		8(%esi)
	movl	%edx,		12(%esi)

	movl	8(%edi),	%eax
	mull	%eax
	movl	%eax,		16(%esi)
	movl	%edx,		20(%esi)

	movl	12(%edi),	%eax
	mull	%eax
	movl	%eax,		24(%esi)
	movl	%edx,		28(%esi)

	movl	16(%edi),	%eax
	mull	%eax
	movl	%eax,		32(%esi)
	movl	%edx,		36(%esi)

	movl	20(%edi),	%eax
	mull	%eax
	movl	%eax,		40(%esi)
	movl	%edx,		44(%esi)

	movl	24(%edi),	%eax
	mull	%eax
	movl	%eax,		48(%esi)
	movl	%edx,		52(%esi)

	movl	28(%edi),	%eax
	mull	%eax
	movl	%eax,		56(%esi)
	movl	%edx,		60(%esi)

	addl	$32,		%edi
	addl	$64,		%esi
	subl	$8,		%ebx
	jnz	.L010sw_loop
.L009sw_finish:
	movl	28(%esp),	%ebx
	andl	$7,		%ebx
	jz	.L011sw_end

	movl	(%edi),		%eax
	mull	%eax
	movl	%eax,		(%esi)
	decl	%ebx
	movl	%edx,		4(%esi)
	jz	.L011sw_end

	movl	4(%edi),	%eax
	mull	%eax
	movl	%eax,		8(%esi)
	decl	%ebx
	movl	%edx,		12(%esi)
	jz	.L011sw_end

	movl	8(%edi),	%eax
	mull	%eax
	movl	%eax,		16(%esi)
	decl	%ebx
	movl	%edx,		20(%esi)
	jz	.L011sw_end

	movl	12(%edi),	%eax
	mull	%eax
	movl	%eax,		24(%esi)
	decl	%ebx
	movl	%edx,		28(%esi)
	jz	.L011sw_end

	movl	16(%edi),	%eax
	mull	%eax
	movl	%eax,		32(%esi)
	decl	%ebx
	movl	%edx,		36(%esi)
	jz	.L011sw_end

	movl	20(%edi),	%eax
	mull	%eax
	movl	%eax,		40(%esi)
	decl	%ebx
	movl	%edx,		44(%esi)
	jz	.L011sw_end

	movl	24(%edi),	%eax
	mull	%eax
	movl	%eax,		48(%esi)
	movl	%edx,		52(%esi)
.L011sw_end:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_sqr_words_end:
.size	bn_sqr_words,.L_bn_sqr_words_end-bn_sqr_words
.ident	"bn_sqr_words"
.text
.globl	bn_div_words
.type	bn_div_words,@function
.align	16
bn_div_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi

	movl	20(%esp),	%edx
	movl	24(%esp),	%eax
	movl	28(%esp),	%ebx
	divl	%ebx
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_div_words_end:
.size	bn_div_words,.L_bn_div_words_end-bn_div_words
.ident	"bn_div_words"
.text
.globl	bn_add_words
.type	bn_add_words,@function
.align	16
bn_add_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	movl	20(%esp),	%ebx
	movl	24(%esp),	%esi
	movl	28(%esp),	%edi
	movl	32(%esp),	%ebp
	xorl	%eax,		%eax
	andl	$4294967288,	%ebp
	jz	.L012aw_finish
.L013aw_loop:

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)

	movl	4(%esi),	%ecx
	movl	4(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		4(%ebx)

	movl	8(%esi),	%ecx
	movl	8(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		8(%ebx)

	movl	12(%esi),	%ecx
	movl	12(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		12(%ebx)

	movl	16(%esi),	%ecx
	movl	16(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		16(%ebx)

	movl	20(%esi),	%ecx
	movl	20(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		20(%ebx)

	movl	24(%esi),	%ecx
	movl	24(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)

	movl	28(%esi),	%ecx
	movl	28(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		28(%ebx)

	addl	$32,		%esi
	addl	$32,		%edi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L013aw_loop
.L012aw_finish:
	movl	32(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L014aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		(%ebx)
	jz	.L014aw_end

	movl	4(%esi),	%ecx
	movl	4(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		4(%ebx)
	jz	.L014aw_end

	movl	8(%esi),	%ecx
	movl	8(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		8(%ebx)
	jz	.L014aw_end

	movl	12(%esi),	%ecx
	movl	12(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		12(%ebx)
	jz	.L014aw_end

	movl	16(%esi),	%ecx
	movl	16(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		16(%ebx)
	jz	.L014aw_end

	movl	20(%esi),	%ecx
	movl	20(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		20(%ebx)
	jz	.L014aw_end

	movl	24(%esi),	%ecx
	movl	24(%edi),	%edx
	addl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	addl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)
.L014aw_end:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_add_words_end:
.size	bn_add_words,.L_bn_add_words_end-bn_add_words
.ident	"bn_add_words"
.text
.globl	bn_sub_words
.type	bn_sub_words,@function
.align	16
bn_sub_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	movl	20(%esp),	%ebx
	movl	24(%esp),	%esi
	movl	28(%esp),	%edi
	movl	32(%esp),	%ebp
	xorl	%eax,		%eax
	andl	$4294967288,	%ebp
	jz	.L015aw_finish
.L016aw_loop:

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)

	movl	4(%esi),	%ecx
	movl	4(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		4(%ebx)

	movl	8(%esi),	%ecx
	movl	8(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		8(%ebx)

	movl	12(%esi),	%ecx
	movl	12(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		12(%ebx)

	movl	16(%esi),	%ecx
	movl	16(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		16(%ebx)

	movl	20(%esi),	%ecx
	movl	20(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		20(%ebx)

	movl	24(%esi),	%ecx
	movl	24(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)

	movl	28(%esi),	%ecx
	movl	28(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		28(%ebx)

	addl	$32,		%esi
	addl	$32,		%edi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L016aw_loop
.L015aw_finish:
	movl	32(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L017aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		(%ebx)
	jz	.L017aw_end

	movl	4(%esi),	%ecx
	movl	4(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		4(%ebx)
	jz	.L017aw_end

	movl	8(%esi),	%ecx
	movl	8(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		8(%ebx)
	jz	.L017aw_end

	movl	12(%esi),	%ecx
	movl	12(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		12(%ebx)
	jz	.L017aw_end

	movl	16(%esi),	%ecx
	movl	16(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		16(%ebx)
	jz	.L017aw_end

	movl	20(%esi),	%ecx
	movl	20(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		20(%ebx)
	jz	.L017aw_end

	movl	24(%esi),	%ecx
	movl	24(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)
.L017aw_end:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_sub_words_end:
.size	bn_sub_words,.L_bn_sub_words_end-bn_sub_words
.ident	"bn_sub_words"
.text
.globl	bn_sub_part_words
.type	bn_sub_part_words,@function
.align	16
bn_sub_part_words:
	pushl	%ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi


	movl	20(%esp),	%ebx
	movl	24(%esp),	%esi
	movl	28(%esp),	%edi
	movl	32(%esp),	%ebp
	xorl	%eax,		%eax
	andl	$4294967288,	%ebp
	jz	.L018aw_finish
.L019aw_loop:

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)

	movl	4(%esi),	%ecx
	movl	4(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		4(%ebx)

	movl	8(%esi),	%ecx
	movl	8(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		8(%ebx)

	movl	12(%esi),	%ecx
	movl	12(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		12(%ebx)

	movl	16(%esi),	%ecx
	movl	16(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		16(%ebx)

	movl	20(%esi),	%ecx
	movl	20(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		20(%ebx)

	movl	24(%esi),	%ecx
	movl	24(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)

	movl	28(%esi),	%ecx
	movl	28(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		28(%ebx)

	addl	$32,		%esi
	addl	$32,		%edi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L019aw_loop
.L018aw_finish:
	movl	32(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
	decl	%ebp
	jz	.L020aw_end

	movl	(%esi),		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)
	addl	$4,		%esi
	addl	$4,		%edi
	addl	$4,		%ebx
.L020aw_end:
	cmpl	$0,		36(%esp)
	je	.L021pw_end
	movl	36(%esp),	%ebp
	cmpl	$0,		%ebp
	je	.L021pw_end
	jge	.L022pw_pos

	movl	$0,		%edx
	subl	%ebp,		%edx
	movl	%edx,		%ebp
	andl	$4294967288,	%ebp
	jz	.L023pw_neg_finish
.L024pw_neg_loop:

	movl	$0,		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		(%ebx)

	movl	$0,		%ecx
	movl	4(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		4(%ebx)

	movl	$0,		%ecx
	movl	8(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		8(%ebx)

	movl	$0,		%ecx
	movl	12(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		12(%ebx)

	movl	$0,		%ecx
	movl	16(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		16(%ebx)

	movl	$0,		%ecx
	movl	20(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		20(%ebx)

	movl	$0,		%ecx
	movl	24(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)

	movl	$0,		%ecx
	movl	28(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		28(%ebx)

	addl	$32,		%edi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L024pw_neg_loop
.L023pw_neg_finish:
	movl	36(%esp),	%edx
	movl	$0,		%ebp
	subl	%edx,		%ebp
	andl	$7,		%ebp
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	(%edi),		%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	4(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		4(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	8(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		8(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	12(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		12(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	16(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		16(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	20(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	decl	%ebp
	movl	%ecx,		20(%ebx)
	jz	.L021pw_end

	movl	$0,		%ecx
	movl	24(%edi),	%edx
	subl	%eax,		%ecx
	movl	$0,		%eax
	adcl	%eax,		%eax
	subl	%edx,		%ecx
	adcl	$0,		%eax
	movl	%ecx,		24(%ebx)
	jmp	.L021pw_end
.L022pw_pos:
	andl	$4294967288,	%ebp
	jz	.L025pw_pos_finish
.L026pw_pos_loop:

	movl	(%esi),		%ecx
	subl	%eax,		%ecx
	movl	%ecx,		(%ebx)
	jnc	.L027pw_nc0

	movl	4(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		4(%ebx)
	jnc	.L028pw_nc1

	movl	8(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		8(%ebx)
	jnc	.L029pw_nc2

	movl	12(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		12(%ebx)
	jnc	.L030pw_nc3

	movl	16(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		16(%ebx)
	jnc	.L031pw_nc4

	movl	20(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		20(%ebx)
	jnc	.L032pw_nc5

	movl	24(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		24(%ebx)
	jnc	.L033pw_nc6

	movl	28(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		28(%ebx)
	jnc	.L034pw_nc7

	addl	$32,		%esi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L026pw_pos_loop
.L025pw_pos_finish:
	movl	36(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L021pw_end

	movl	(%esi),		%ecx
	subl	%eax,		%ecx
	movl	%ecx,		(%ebx)
	jnc	.L035pw_tail_nc0
	decl	%ebp
	jz	.L021pw_end

	movl	4(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		4(%ebx)
	jnc	.L036pw_tail_nc1
	decl	%ebp
	jz	.L021pw_end

	movl	8(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		8(%ebx)
	jnc	.L037pw_tail_nc2
	decl	%ebp
	jz	.L021pw_end

	movl	12(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		12(%ebx)
	jnc	.L038pw_tail_nc3
	decl	%ebp
	jz	.L021pw_end

	movl	16(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		16(%ebx)
	jnc	.L039pw_tail_nc4
	decl	%ebp
	jz	.L021pw_end

	movl	20(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		20(%ebx)
	jnc	.L040pw_tail_nc5
	decl	%ebp
	jz	.L021pw_end

	movl	24(%esi),	%ecx
	subl	%eax,		%ecx
	movl	%ecx,		24(%ebx)
	jnc	.L041pw_tail_nc6
	movl	$1,		%eax
	jmp	.L021pw_end
.L042pw_nc_loop:
	movl	(%esi),		%ecx
	movl	%ecx,		(%ebx)
.L027pw_nc0:
	movl	4(%esi),	%ecx
	movl	%ecx,		4(%ebx)
.L028pw_nc1:
	movl	8(%esi),	%ecx
	movl	%ecx,		8(%ebx)
.L029pw_nc2:
	movl	12(%esi),	%ecx
	movl	%ecx,		12(%ebx)
.L030pw_nc3:
	movl	16(%esi),	%ecx
	movl	%ecx,		16(%ebx)
.L031pw_nc4:
	movl	20(%esi),	%ecx
	movl	%ecx,		20(%ebx)
.L032pw_nc5:
	movl	24(%esi),	%ecx
	movl	%ecx,		24(%ebx)
.L033pw_nc6:
	movl	28(%esi),	%ecx
	movl	%ecx,		28(%ebx)
.L034pw_nc7:

	addl	$32,		%esi
	addl	$32,		%ebx
	subl	$8,		%ebp
	jnz	.L042pw_nc_loop
	movl	36(%esp),	%ebp
	andl	$7,		%ebp
	jz	.L043pw_nc_end
	movl	(%esi),		%ecx
	movl	%ecx,		(%ebx)
.L035pw_tail_nc0:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	4(%esi),	%ecx
	movl	%ecx,		4(%ebx)
.L036pw_tail_nc1:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	8(%esi),	%ecx
	movl	%ecx,		8(%ebx)
.L037pw_tail_nc2:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	12(%esi),	%ecx
	movl	%ecx,		12(%ebx)
.L038pw_tail_nc3:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	16(%esi),	%ecx
	movl	%ecx,		16(%ebx)
.L039pw_tail_nc4:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	20(%esi),	%ecx
	movl	%ecx,		20(%ebx)
.L040pw_tail_nc5:
	decl	%ebp
	jz	.L043pw_nc_end
	movl	24(%esi),	%ecx
	movl	%ecx,		24(%ebx)
.L041pw_tail_nc6:
.L043pw_nc_end:
	movl	$0,		%eax
.L021pw_end:
	popl	%edi
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret
.L_bn_sub_part_words_end:
.size	bn_sub_part_words,.L_bn_sub_part_words_end-bn_sub_part_words
.ident	"bn_sub_part_words"

.section	.bss
