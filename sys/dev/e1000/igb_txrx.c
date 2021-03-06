/*-
 * Copyright (c) 2016 Matt Macy <mmacy@nextbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* $FreeBSD$ */
#include "if_em.h"

#ifdef	RSS
#include <net/rss_config.h>
#include <netinet/in_rss.h>
#endif

#ifdef VERBOSE_DEBUG
#define DPRINTF device_printf
#else
#define DPRINTF(...)
#endif

/*********************************************************************
 *  Local Function prototypes
 *********************************************************************/
static int igb_isc_txd_encap(void *arg, if_pkt_info_t pi);
static void igb_isc_txd_flush(void *arg, uint16_t txqid, uint32_t pidx);
static int igb_isc_txd_credits_update(void *arg, uint16_t txqid, uint32_t cidx, bool clear);

static void igb_isc_rxd_refill(void *arg, uint16_t rxqid, uint8_t flid __unused,
			       uint32_t pidx, uint64_t *paddrs, caddr_t *vaddrs __unused, uint16_t count, uint16_t buf_len __unused);
static void igb_isc_rxd_flush(void *arg, uint16_t rxqid, uint8_t flid __unused, uint32_t pidx);
static int igb_isc_rxd_available(void *arg, uint16_t rxqid, uint32_t idx,
				 int budget);
static int igb_isc_rxd_pkt_get(void *arg, if_rxd_info_t ri);

static int igb_tx_ctx_setup(struct tx_ring *txr, if_pkt_info_t pi, u32 *cmd_type_len, u32 *olinfo_status);
static int igb_tso_setup(struct tx_ring *txr, if_pkt_info_t pi, u32 *cmd_type_len, u32 *olinfo_status);

static void igb_rx_checksum(u32 staterr, if_rxd_info_t ri, u32 ptype);
static int igb_determine_rsstype(u16 pkt_info);	

extern void igb_if_enable_intr(if_ctx_t ctx);
extern int em_intr(void *arg);

struct if_txrx igb_txrx  = {
	igb_isc_txd_encap,
	igb_isc_txd_flush,
	igb_isc_txd_credits_update,
	igb_isc_rxd_available,
	igb_isc_rxd_pkt_get,
	igb_isc_rxd_refill,
	igb_isc_rxd_flush,
	em_intr
};

extern if_shared_ctx_t em_sctx;

/**********************************************************************
 *
 *  Setup work for hardware segmentation offload (TSO) on
 *  adapters using advanced tx descriptors
 *
 **********************************************************************/
static int
igb_tso_setup(struct tx_ring *txr, if_pkt_info_t pi, u32 *cmd_type_len, u32 *olinfo_status)
{
	struct e1000_adv_tx_context_desc *TXD;
	struct adapter *adapter = txr->adapter; 
       u32 type_tucmd_mlhl = 0, vlan_macip_lens = 0;
       u32 mss_l4len_idx = 0; 
       u32 paylen; 
        
       switch(pi->ipi_etype) {
         case ETHERTYPE_IPV6:
            type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV6;
            break;
         case ETHERTYPE_IP:
            type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV4;
            /* Tell transmit desc to also do IPv4 checksum. */
            *olinfo_status |= E1000_TXD_POPTS_IXSM << 8;
            break;
         default:
            panic("%s: CSUM_TSO but no supported IP version (0x%04x)",
	         __func__, ntohs(pi->ipi_etype));
            break;
        }

        TXD = (struct e1000_adv_tx_context_desc *) &txr->tx_base[pi->ipi_pidx];

        /* This is used in the transmit desc in encap */
        paylen = pi->ipi_len - pi->ipi_ehdrlen - pi->ipi_ip_hlen - pi->ipi_tcp_hlen;

  	/* VLAN MACLEN IPLEN */
	if (pi->ipi_mflags & M_VLANTAG) {
                vlan_macip_lens |= (pi->ipi_vtag << E1000_ADVTXD_VLAN_SHIFT);
	}

	vlan_macip_lens |= pi->ipi_ehdrlen << E1000_ADVTXD_MACLEN_SHIFT;
	vlan_macip_lens |= pi->ipi_ip_hlen;
	TXD->vlan_macip_lens = htole32(vlan_macip_lens);

	/* ADV DTYPE TUCMD */
	type_tucmd_mlhl |= E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_CTXT;
	type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_TCP;
	TXD->type_tucmd_mlhl = htole32(type_tucmd_mlhl);

	/* MSS L4LEN IDX */
	mss_l4len_idx |= (pi->ipi_tso_segsz << E1000_ADVTXD_MSS_SHIFT);
	mss_l4len_idx |= (pi->ipi_tcp_hlen << E1000_ADVTXD_L4LEN_SHIFT);
	/* 82575 needs the queue index added */
	if (adapter->hw.mac.type == e1000_82575)
		mss_l4len_idx |= txr->me << 4;
	TXD->mss_l4len_idx = htole32(mss_l4len_idx);

	TXD->seqnum_seed = htole32(0);
        *cmd_type_len |= E1000_ADVTXD_DCMD_TSE;
	*olinfo_status |= E1000_TXD_POPTS_TXSM << 8;
	*olinfo_status |= paylen << E1000_ADVTXD_PAYLEN_SHIFT;
  
        return (1);
}

/*********************************************************************
 *
 *  Advanced Context Descriptor setup for VLAN, CSUM or TSO
 *
 **********************************************************************/
static int
igb_tx_ctx_setup(struct tx_ring *txr, if_pkt_info_t pi, u32 *cmd_type_len, u32 *olinfo_status)
{
        struct e1000_adv_tx_context_desc *TXD;
	struct adapter *adapter = txr->adapter; 
        u32 vlan_macip_lens, type_tucmd_mlhl;
	u32 mss_l4len_idx;
	mss_l4len_idx = vlan_macip_lens = type_tucmd_mlhl = 0;
	int offload = TRUE; 

        /* First check if TSO is to be used */
	if (pi->ipi_csum_flags & CSUM_TSO)
		return (igb_tso_setup(txr, pi, cmd_type_len, olinfo_status));

        /* Indicate the whole packet as payload when not doing TSO */
       	*olinfo_status |= pi->ipi_len << E1000_ADVTXD_PAYLEN_SHIFT;

	/* Now ready a context descriptor */
	TXD = (struct e1000_adv_tx_context_desc *) &txr->tx_base[pi->ipi_pidx];

        /*
	** In advanced descriptors the vlan tag must 
	** be placed into the context descriptor. Hence
	** we need to make one even if not doing offloads.
	*/
        if (pi->ipi_mflags & M_VLANTAG) {
		vlan_macip_lens |= (pi->ipi_vtag << E1000_ADVTXD_VLAN_SHIFT);
	} else if ((pi->ipi_csum_flags & IGB_CSUM_OFFLOAD) == 0) {
		return (0);
	}
	
	/* Set the ether header length */
	vlan_macip_lens |= pi->ipi_ehdrlen << E1000_ADVTXD_MACLEN_SHIFT;

	switch(pi->ipi_etype) {
	    case ETHERTYPE_IP:
	         type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV4;
                 break;
	    case ETHERTYPE_IPV6:
                 type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_IPV6;
                 break;
            default:
	         offload = FALSE; 
                 break;
	}
	
        vlan_macip_lens |= pi->ipi_ip_hlen;
	type_tucmd_mlhl |= E1000_ADVTXD_DCMD_DEXT | E1000_ADVTXD_DTYP_CTXT;

	switch (pi->ipi_ipproto) {
	       case IPPROTO_TCP:
                #if __FreeBSD_version >= 1000000
			if (pi->ipi_csum_flags & (CSUM_IP_TCP | CSUM_IP6_TCP))
#else
			if (pi->ipi_csum_flags & CSUM_TCP)
#endif
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_TCP;
			break;
		case IPPROTO_UDP:
#if __FreeBSD_version >= 1000000
			if (pi->ipi_csum_flags & (CSUM_IP_UDP | CSUM_IP6_UDP))
#else
			if (pi->ipi_csum_flags & CSUM_UDP)
#endif
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_UDP;
			break;

#if __FreeBSD_version >= 800000
		case IPPROTO_SCTP:
#if __FreeBSD_version >= 1000000
			if (pi->ipi_csum_flags & (CSUM_IP_SCTP | CSUM_IP6_SCTP))
#else
			if (pi->ipi_csum_flags & CSUM_SCTP)
#endif
				type_tucmd_mlhl |= E1000_ADVTXD_TUCMD_L4T_SCTP;
			break;
#endif
		default:
			offload = FALSE;
			break;
	}

	if (offload) /* For the TX descriptor setup */
	  *olinfo_status |= E1000_TXD_POPTS_TXSM << 8;

	/* 82575 needs the queue index added */
	if (adapter->hw.mac.type == e1000_82575)
		mss_l4len_idx = txr->me << 4;
	
	/* Now copy bits into descriptor */
	TXD->vlan_macip_lens = htole32(vlan_macip_lens);
	TXD->type_tucmd_mlhl = htole32(type_tucmd_mlhl);
	TXD->seqnum_seed = htole32(0);
	TXD->mss_l4len_idx = htole32(mss_l4len_idx);
	
	return (1);
}

static int
igb_isc_txd_encap(void *arg, if_pkt_info_t pi)
{
	struct adapter *sc        = arg;
	if_softc_ctx_t scctx      = sc->shared;
	struct em_tx_queue *que  = &sc->tx_queues[pi->ipi_qsidx];
	struct tx_ring *txr       = &que->txr;
	int nsegs                 = pi->ipi_nsegs;
	bus_dma_segment_t *segs   = pi->ipi_segs;
	struct em_txbuffer *txbuf;
	union e1000_adv_tx_desc *txd = NULL;  
	
	int                    i, j, first, pidx_last;
	u32                    olinfo_status, cmd_type_len;

	pidx_last = olinfo_status = 0;
	/* Basic descriptor defines */
	cmd_type_len = (E1000_ADVTXD_DTYP_DATA |
					E1000_ADVTXD_DCMD_IFCS | E1000_ADVTXD_DCMD_DEXT);
	
	if (pi->ipi_mflags & M_VLANTAG)
		cmd_type_len |= E1000_ADVTXD_DCMD_VLE;

	first = i = pi->ipi_pidx;

	/* Consume the first descriptor */
        i += igb_tx_ctx_setup(txr, pi, &cmd_type_len, &olinfo_status);
        if (i == scctx->isc_ntxd[0])
		i = 0;
	
	/* 82575 needs the queue index added */
	if (sc->hw.mac.type == e1000_82575)
		olinfo_status |= txr->me << 4;
	
	for (j = 0; j < nsegs; j++) {
		bus_size_t seglen;
		bus_addr_t segaddr;

		txbuf = &txr->tx_buffers[i];
		txd = (union e1000_adv_tx_desc *)&txr->tx_base[i];
		seglen = segs[j].ds_len;
		segaddr = htole64(segs[j].ds_addr);

		txd->read.buffer_addr = segaddr;
		txd->read.cmd_type_len = htole32(E1000_TXD_CMD_IFCS |
		    cmd_type_len | seglen);
		txd->read.olinfo_status = htole32(olinfo_status);
		pidx_last = i;
		if (++i == scctx->isc_ntxd[0]) {
			i = 0;
		}
	}
	
	txd->read.cmd_type_len |=
	    htole32(E1000_TXD_CMD_EOP | E1000_TXD_CMD_RS);
		
	/* Set the EOP descriptor that will be marked done */
	txbuf = &txr->tx_buffers[first]; 
	txbuf->eop = pidx_last;

	pi->ipi_new_pidx = i;
  
	return (0);
}

static void
igb_isc_txd_flush(void *arg, uint16_t txqid, uint32_t pidx)
{
       struct adapter *adapter      = arg;
       struct em_tx_queue *que     = &adapter->tx_queues[txqid];
       struct tx_ring *txr          = &que->txr;
  
       E1000_WRITE_REG(&adapter->hw, E1000_TDT(txr->me), pidx);
}

static int
igb_isc_txd_credits_update(void *arg, uint16_t txqid, uint32_t cidx_init, bool clear)
{
	struct adapter      *adapter = arg;
	if_softc_ctx_t      scctx = adapter->shared; 
	struct em_tx_queue *que = &adapter->tx_queues[txqid];
	struct tx_ring      *txr = &que->txr;

	u32       cidx, ntxd, processed = 0;

	struct em_txbuffer *buf;
	union e1000_adv_tx_desc *txd, *eop;
        int limit;
	
	cidx = cidx_init;

	buf = &txr->tx_buffers[cidx];
	txd = (union e1000_adv_tx_desc *)&txr->tx_base[cidx];
	ntxd = scctx->isc_ntxd[0];
	limit = adapter->tx_process_limit; 

	do {
		if (buf->eop == -1) /* No work */
			break;

		eop = (union e1000_adv_tx_desc *)&txr->tx_base[buf->eop];
		if ((eop->wb.status & E1000_TXD_STAT_DD) == 0)
			break;	/* I/O not complete */
		
		if (clear)
			buf->eop = -1; /* clear indicate processed */

                /* We clean the range if multi segment */
		while (txd != eop) {
			++txd;
			++buf;
			/* wrap the ring? */
			if (++cidx == scctx->isc_ntxd[0]) {
				cidx = 0;
				buf = txr->tx_buffers;
				txd = (union e1000_adv_tx_desc *)txr->tx_base;
			}
		 
			buf = &txr->tx_buffers[cidx];
			if (clear)
				buf->eop = -1; 
			processed++; 
		}
		processed++;

		/* Try the next packet */
		txd++;
		buf++;
	    
		/* reset with a wrap */
		if (++cidx == scctx->isc_ntxd[0]) {
			cidx = 0;
			buf = txr->tx_buffers;
			txd = (union e1000_adv_tx_desc *)txr->tx_base;
		}
		prefetch(txd);
		prefetch(txd+1);
	} while (__predict_true(--limit) && cidx != cidx_init);
	
	return (processed);
}

static void
igb_isc_rxd_refill(void *arg, uint16_t rxqid, uint8_t flid __unused,
		   uint32_t pidx, uint64_t *paddrs, caddr_t *vaddrs __unused,
		   uint16_t count, uint16_t buf_len __unused)
{
	struct adapter *sc           = arg;
	if_softc_ctx_t scctx         = sc->shared; 
	struct em_rx_queue *que     = &sc->rx_queues[rxqid];
	union e1000_adv_rx_desc *rxd;
	struct rx_ring *rxr          = &que->rxr;
	int			     i;
	uint32_t next_pidx;

	for (i = 0, next_pidx = pidx; i < count; i++) {
		rxd = (union e1000_adv_rx_desc *)&rxr->rx_base[next_pidx];

		rxd->read.pkt_addr = htole64(paddrs[i]);
		if (++next_pidx == scctx->isc_nrxd[0])
			next_pidx = 0;
	}
}

static void
igb_isc_rxd_flush(void *arg, uint16_t rxqid, uint8_t flid __unused, uint32_t pidx)
{
	struct adapter *sc           = arg;
	struct em_rx_queue *que     = &sc->rx_queues[rxqid];
	struct rx_ring *rxr          = &que->rxr;

	E1000_WRITE_REG(&sc->hw, E1000_RDT(rxr->me), pidx);
}

static int
igb_isc_rxd_available(void *arg, uint16_t rxqid, uint32_t idx, int budget)
{
	struct adapter *sc           = arg;
	if_softc_ctx_t scctx         = sc->shared; 
	struct em_rx_queue *que     = &sc->rx_queues[rxqid];
	struct rx_ring *rxr      = &que->rxr;
	union e1000_adv_rx_desc *rxd;
	u32                      staterr = 0;
	int                      cnt, i, iter;

	for (iter = cnt = 0, i = idx; iter < scctx->isc_nrxd[0] && iter <= budget;) {
		rxd = (union e1000_adv_rx_desc *)&rxr->rx_base[i];
		staterr = le32toh(rxd->wb.upper.status_error);	
		
		if ((staterr & E1000_RXD_STAT_DD) == 0)
			break;
		
		if (++i == scctx->isc_nrxd[0]) {
			i = 0;
		}

		if (staterr & E1000_RXD_STAT_EOP)
			cnt++;
		iter++;
	}
	{
		struct e1000_hw *hw = &sc->hw;
		int rdt, rdh;
		rdt = E1000_READ_REG(hw, E1000_RDT(rxr->me));
		rdh = E1000_READ_REG(hw, E1000_RDH(rxr->me));
		DPRINTF(iflib_get_dev(sc->ctx), "sidx:%d eidx:%d iter=%d pktcnt=%d RDT=%d RDH=%d\n", idx, i, iter, cnt, rdt, rdh);
	}
	return (cnt);
}

/****************************************************************
 * Routine sends data which has been dma'ed into host memory
 * to upper layer. Initialize ri structure. 
 *
 * Returns 0 upon success, errno on failure
 ***************************************************************/

static int
igb_isc_rxd_pkt_get(void *arg, if_rxd_info_t ri)
{
	struct adapter           *adapter = arg;
	if_softc_ctx_t           scctx = adapter->shared; 
	struct em_rx_queue      *que = &adapter->rx_queues[ri->iri_qsidx];
	struct rx_ring           *rxr = &que->rxr;
	struct ifnet             *ifp = iflib_get_ifp(adapter->ctx);
	union e1000_adv_rx_desc  *rxd;

	u16                      pkt_info, len;
	u16                      vtag = 0;
	u32                      ptype;
	u32                      staterr = 0;
	bool                     eop;
	int                      i = 0; 
	int                      cidx = ri->iri_cidx;

	do {
		rxd = (union e1000_adv_rx_desc *)&rxr->rx_base[cidx];
		staterr = le32toh(rxd->wb.upper.status_error);
		pkt_info = le16toh(rxd->wb.lower.lo_dword.hs_rss.pkt_info);
		
		MPASS ((staterr & E1000_RXD_STAT_DD) != 0);

		len = le16toh(rxd->wb.upper.length);
		ptype = le32toh(rxd->wb.lower.lo_dword.data) &  IGB_PKTTYPE_MASK;

		ri->iri_len += len;
		rxr->rx_bytes += ri->iri_len; 

		rxd->wb.upper.status_error = 0;
		eop = ((staterr & E1000_RXD_STAT_EOP) == E1000_RXD_STAT_EOP);

		if (((adapter->hw.mac.type == e1000_i350) ||
		     (adapter->hw.mac.type == e1000_i354)) &&
		    (staterr & E1000_RXDEXT_STATERR_LB))
			vtag = be16toh(rxd->wb.upper.vlan);
		else
			vtag = le16toh(rxd->wb.upper.vlan);

		/* Make sure bad packets are discarded */
		if (eop && ((staterr & E1000_RXDEXT_ERR_FRAME_ERR_MASK) != 0)) {
			adapter->dropped_pkts++;
			++rxr->rx_discarded;
			return (EBADMSG);
		}
		ri->iri_frags[i].irf_flid = 0;
		ri->iri_frags[i].irf_idx = cidx;
		ri->iri_frags[i].irf_len = len;
	
		if (++cidx == scctx->isc_nrxd[0])
			cidx = 0;
#ifdef notyet		
		if (rxr->hdr_split == TRUE) {
			ri->iri_frags[i].irf_flid = 1;
			ri->iri_frags[i].irf_idx = cidx; 
			if (++cidx == scctx->isc_nrxd[0])
				cidx = 0;
		}
#endif		
		i++;
	} while (!eop);
	
	rxr->rx_packets++;

	if ((ifp->if_capenable & IFCAP_RXCSUM) != 0)
		igb_rx_checksum(staterr, ri, ptype);
	
	if ((ifp->if_capenable & IFCAP_VLAN_HWTAGGING) != 0 &&
	    (staterr & E1000_RXD_STAT_VP) != 0) {
		ri->iri_vtag = vtag;
		ri->iri_flags |= M_VLANTAG;
	}
	ri->iri_flowid =
		le32toh(rxd->wb.lower.hi_dword.rss);
	ri->iri_rsstype = igb_determine_rsstype(pkt_info);
	ri->iri_nfrags = i;

	return (0); 
}

/*********************************************************************
 *
 *  Verify that the hardware indicated that the checksum is valid.
 *  Inform the stack about the status of checksum so that stack
 *  doesn't spend time verifying the checksum.
 *
 *********************************************************************/
static void
igb_rx_checksum(u32 staterr, if_rxd_info_t ri, u32 ptype)
{
	u16 status = (u16)staterr;
	u8  errors = (u8) (staterr >> 24);
	bool sctp = FALSE; 

	/* Ignore Checksum bit is set */
	if (status & E1000_RXD_STAT_IXSM) {
		ri->iri_csum_flags = 0;
		return;
	}

	if ((ptype & E1000_RXDADV_PKTTYPE_ETQF) == 0 &&
	    (ptype & E1000_RXDADV_PKTTYPE_SCTP) != 0)
		sctp = 1;
	else
		sctp = 0;

	if (status & E1000_RXD_STAT_IPCS) {
		/* Did it pass? */
		if (!(errors & E1000_RXD_ERR_IPE)) {
			/* IP Checksum Good */
			ri->iri_csum_flags = CSUM_IP_CHECKED;
			ri->iri_csum_flags |= CSUM_IP_VALID;
		} else
			ri->iri_csum_flags = 0;
	}

	if (status & (E1000_RXD_STAT_TCPCS | E1000_RXD_STAT_UDPCS)) {
		u64 type = (CSUM_DATA_VALID | CSUM_PSEUDO_HDR);
#if __FreeBSD_version >= 800000
		if (sctp) /* reassign */
			type = CSUM_SCTP_VALID;
#endif
		/* Did it pass? */
		if (!(errors & E1000_RXD_ERR_TCPE)) {
			ri->iri_csum_flags |= type;
			if (sctp == 0)
				ri->iri_csum_data = htons(0xffff);
		}
	}
	return;
}

/********************************************************************
 *
 *  Parse the packet type to determine the appropriate hash
 *
 ******************************************************************/
static int 
igb_determine_rsstype(u16 pkt_info)	
{
   	switch (pkt_info & E1000_RXDADV_RSSTYPE_MASK) {
	case E1000_RXDADV_RSSTYPE_IPV4_TCP:
		return M_HASHTYPE_RSS_TCP_IPV4;
	case E1000_RXDADV_RSSTYPE_IPV4:
		return M_HASHTYPE_RSS_IPV4;
	case E1000_RXDADV_RSSTYPE_IPV6_TCP:
		return M_HASHTYPE_RSS_TCP_IPV6;
	case E1000_RXDADV_RSSTYPE_IPV6_EX:
		return M_HASHTYPE_RSS_IPV6_EX;
	case E1000_RXDADV_RSSTYPE_IPV6:
		return M_HASHTYPE_RSS_IPV6;
	case E1000_RXDADV_RSSTYPE_IPV6_TCP_EX:
		return M_HASHTYPE_RSS_TCP_IPV6_EX;
	default:
		return M_HASHTYPE_OPAQUE;
	}
}
