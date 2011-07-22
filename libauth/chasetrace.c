/*
 * chasetrace.c
 * Where all the hard work concerning chasing
 * and tracing is done
 * (c) 2005, 2006 NLnet Labs
 *
 * See the file LICENSE for the license
 *
 */

#include <ldns/ldns.h>

#define HAVE_SSL

/**
 * Chase the given rr to a known and trusted key
 *
 * Based on drill 0.9
 *
 * the last argument prev_key_list, if not null, and type == DS, then the ds
 * rr list we have must all be a ds for the keys in this list
 */
#ifdef HAVE_SSL
ldns_status
do_chase(ldns_resolver *res,
	    ldns_rdf *name,
	    ldns_rr_type type,
	    ldns_rr_class c,
	    ldns_rr_list *trusted_keys,
	    ldns_pkt *pkt_o,
	    uint16_t qflags,
	    ldns_rr_list *prev_key_list,
	    int verbosity)
{
	ldns_rr_list *rrset = NULL;
	ldns_status result;
	ldns_rr *orig_rr = NULL;
	
/*
	ldns_rr_list *sigs;
	ldns_rr *cur_sig;
	uint16_t sig_i;
	ldns_rr_list *keys;
*/
	ldns_pkt *pkt;
	ldns_status tree_result;
	ldns_dnssec_data_chain *chain;
	ldns_dnssec_trust_tree *tree;
	
	const ldns_rr_descriptor *descriptor;
	descriptor = ldns_rr_descript(type);

	ldns_dname2canonical(name);
	
	pkt = ldns_pkt_clone(pkt_o);
	if (!name) {
		ldns_pkt_free(pkt);
		return LDNS_STATUS_EMPTY_LABEL;
	}
	if (verbosity != -1) {
		printf(";; Chasing: ");
			ldns_rdf_print(stdout, name);
			if (descriptor && descriptor->_name) {
				printf(" %s\n", descriptor->_name);
			} else {
				printf(" type %d\n", type);
			}
	}

	if (!trusted_keys || ldns_rr_list_rr_count(trusted_keys) < 1) {
	}
	
	if (pkt) {
		rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
				name,
				type,
				LDNS_SECTION_ANSWER
				);
		if (!rrset) {
			/* nothing in answer, try authority */
			rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
					name,
					type,
					LDNS_SECTION_AUTHORITY
					);
		}
		/* answer might be a cname, chase that first, then chase
		   cname target? (TODO) */
		if (!rrset) {
			rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
					name,
					LDNS_RR_TYPE_CNAME,
					LDNS_SECTION_ANSWER
					);
			if (!rrset) {
				/* nothing in answer, try authority */
				rrset = ldns_pkt_rr_list_by_name_and_type(pkt,
						name,
						LDNS_RR_TYPE_CNAME,
						LDNS_SECTION_AUTHORITY
						);
			}
		}
	} else {
		/* no packet? */
		if (verbosity >= 0) {
			fprintf(stderr, "%s", ldns_get_errorstr_by_id(LDNS_STATUS_MEM_ERR));
			fprintf(stderr, "\n");
		}
		return LDNS_STATUS_MEM_ERR;
	}
	
	if (!rrset) {
		/* not found in original packet, try again */
		ldns_pkt_free(pkt);
		pkt = NULL;
		pkt = ldns_resolver_query(res, name, type, c, qflags);
		
		if (!pkt) {
			if (verbosity >= 0) {
				fprintf(stderr, "%s", ldns_get_errorstr_by_id(LDNS_STATUS_NETWORK_ERR));
				fprintf(stderr, "\n");
			}
			return LDNS_STATUS_NETWORK_ERR;
		}
		if (verbosity >= 5) {
			ldns_pkt_print(stdout, pkt);
		}
		
		rrset =	ldns_pkt_rr_list_by_name_and_type(pkt,
				name,
				type,
				LDNS_SECTION_ANSWER
				);
	}
	
	orig_rr = ldns_rr_new();

/* if the answer had no answer section, we need to construct our own rr (for instance if
 * the rr qe asked for doesn't exist. This rr will be destroyed when the chain is freed */
	if (ldns_pkt_ancount(pkt) < 1) {
		ldns_rr_set_type(orig_rr, type);
		ldns_rr_set_owner(orig_rr, ldns_rdf_clone(name));
	
		chain = ldns_dnssec_build_data_chain(res, qflags, rrset, pkt, ldns_rr_clone(orig_rr));
	} else {
		/* chase the first answer */
		chain = ldns_dnssec_build_data_chain(res, qflags, rrset, pkt, NULL);
	}

	if (verbosity >= 4) {
		printf("\n\nDNSSEC Data Chain:\n");
		ldns_dnssec_data_chain_print(stdout, chain);
	}
	
	result = LDNS_STATUS_OK;

	tree = ldns_dnssec_derive_trust_tree(chain, NULL);

	if (verbosity >= 2) {
		printf("\n\nDNSSEC Trust tree:\n");
		ldns_dnssec_trust_tree_print(stdout, tree, 0, true);
	}

	if (ldns_rr_list_rr_count(trusted_keys) > 0) {
		tree_result = ldns_dnssec_trust_tree_contains_keys(tree, trusted_keys);

		if (tree_result == LDNS_STATUS_DNSSEC_EXISTENCE_DENIED) {
			if (verbosity >= 1) {
				printf("Existence denied or verifiably insecure\n");
			}
			result = LDNS_STATUS_OK;
		} else if (tree_result != LDNS_STATUS_OK) {
			if (verbosity >= 1) {
				printf("No trusted keys found in tree: first error was: %s\n", ldns_get_errorstr_by_id(tree_result));
			}
			result = tree_result;
		}

	} else {
		result = -1;
		if (verbosity >= 0) {
			printf("You have not provided any trusted keys.\n");
		}
	}
	
	ldns_rr_free(orig_rr);
	ldns_dnssec_trust_tree_free(tree);
	ldns_dnssec_data_chain_deep_free(chain);
	
	ldns_rr_list_deep_free(rrset);
	ldns_pkt_free(pkt);
	/*	ldns_rr_free(orig_rr);*/

	return result;
}
#endif /* HAVE_SSL */

/* drill_util.c */

static int
read_line(FILE *input, char *line)
{       
        int i;

        char c;
        for (i = 0; i < LDNS_MAX_PACKETLEN; i++) {
                c = getc(input);
                if (c == EOF) {
                        return -1;
                } else if (c != '\n') {
                        line[i] = c;
                } else {
                        break;
                }
        }
        line[i] = '\0';
        return i;
}

/* key_list must be initialized with ldns_rr_list_new() */
ldns_status
read_key_file(const char *filename, ldns_rr_list *key_list)
{       
        int line_len = 0;
        int line_nr = 0;
        int key_count = 0;
        char line[LDNS_MAX_PACKETLEN];
        ldns_status status;
        FILE *input_file;
        ldns_rr *rr;

        input_file = fopen(filename, "r");
        if (!input_file) {
                fprintf(stderr, "Error opening %s: %s\n",
                        filename, strerror(errno));
                return LDNS_STATUS_ERR;
        }
        while (line_len >= 0) {
                line_len = read_line(input_file, line);
                line_nr++;
                if (line_len > 0 && line[0] != ';') {
                        status = ldns_rr_new_frm_str(&rr, line, 0, NULL, NULL);
                        if (status != LDNS_STATUS_OK) {
                                fprintf(stderr,
                                                "Error parsing DNSKEY RR in line %d: %s\n",
                                                line_nr,
                                                ldns_get_errorstr_by_id(status));
                        } else if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_DNSKEY ||
                                           ldns_rr_get_type(rr) == LDNS_RR_TYPE_DS) {
                                ldns_rr_list_push_rr(key_list, rr);
                                key_count++;
                        } else {
                                ldns_rr_free(rr);
                        }
                }
        }
//        printf(";; Number of trusted keys: %d\n", key_count);
        if (key_count > 0) {
                return LDNS_STATUS_OK;
        } else {
                /*fprintf(stderr, "No keys read\n");*/
                return LDNS_STATUS_ERR;
        }
}
