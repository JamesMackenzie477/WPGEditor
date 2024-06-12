#include "Cryptor.h"

// creates a need seeded cryptor instance
Cryptor::Cryptor(PDWORD pSeed, PDWORD pBlock)
{
	// validates the parameters
	if (pSeed && pBlock)
	{
		// adds the block to the class
		this->Block[0] = pBlock[0];
		this->Block[1] = pBlock[1];
		this->Block[2] = pBlock[2];
		this->Block[3] = pBlock[3];
		// splits the seed into four segments for manipulation
		DWORD v5 = pSeed[0];
		DWORD v6 = pSeed[1];
		DWORD v8 = pSeed[2];
		DWORD v9 = pSeed[3];
		// creates the encryption and decryption key
		DWORD v7 = v6;
		DWORD v10 = __ROL4__(v5, 8);
		v6 = __ROL4__(v6, 8);
		DWORD v11 = __ROR4__(v5, 8);
		v7 = __ROR4__(v7, 8);
		DWORD v12 = v6 & 0xFF00FF | v7 & 0xFF00FF00;
		DWORD v78 = v10 & 0xFF00FF | v11 & 0xFF00FF00;
		DWORD v13 = __ROR4__(v8, 8);
		DWORD v14 = __ROR4__(v9, 8);
		v8 = __ROL4__(v8, 8);
		v9 = __ROL4__(v9, 8);
		DWORD v15 = v9 & 0xFF00FF | v14 & 0xFF00FF00;
		DWORD v74 = v8 & 0xFF00FF | v13 & 0xFF00FF00;
		DWORD v16 = v15;
		DWORD v17 = v74 + v78 + 0x61C88647;
		DWORD v18 = v12 - v15 - 1640531527;
		
		this->Key[0] = dword_AF8C00[(unsigned __int8)(v74 + v78 + 0x47)] ^ dword_AF9000[BYTE1(v17)] ^ dword_AF9400[(unsigned __int8)((v74 + v78 + 0x61C88647) >> 16)] ^ dword_AF9800[(v74 + v78 + 0x61C88647) >> 24];
		this->Key[1] = dword_AF8C00[(unsigned __int8)(v12 - v15 - 71)] ^ dword_AF9000[BYTE1(v18)] ^ dword_AF9400[(unsigned __int8)(v18 >> 0x10)] ^ dword_AF9800[v18 >> 0x18];
		
		DWORD v19 = (unsigned __int64)v78 >> 8;
		DWORD v79 = (v12 >> 8) ^ (v78 << 24);
		DWORD v20 = v19 ^ (v12 << 24);
		DWORD v21 = v79 - v16 + 1013904243;
		
		this->Key[2] = dword_AF8C00[(unsigned __int8)(v20 + v74 - 115)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v20 + v74 + 3213) >> 8)] ^ dword_AF9400[(unsigned __int8)((v20 + v74 - 1013904243) >> 16)] ^ dword_AF9800[(v20 + v74 - 1013904243) >> 24];
		this->Key[3] = dword_AF8C00[(unsigned __int8)(v79 - v16 + 115)] ^ dword_AF9000[BYTE1(v21)] ^ dword_AF9400[(unsigned __int8)(v21 >> 16)] ^ dword_AF9800[v21 >> 24];
		
		DWORD v22 = ((v74 << 8) ^ (v16 >> 24)) + v20 - 0x78DDE6E6;
		DWORD v23 = (v16 << 8) ^ (v74 >> 24);
		DWORD v24 = (v74 << 8) ^ (v16 >> 24);
		DWORD v25 = v79;
		DWORD v26 = v79 - v23 + 2027808486;
		
		this->Key[4] = dword_AF8C00[(unsigned __int8)(BYTE3(v16) + v20 + 0x1A)] ^ dword_AF9000[BYTE1(v22)] ^ dword_AF9400[(unsigned __int8)(v22 >> 16)] ^ dword_AF9800[v22 >> 24];
		this->Key[5] = dword_AF8C00[(unsigned __int8)(v79 - BYTE3(v74) - 26)] ^ dword_AF9000[BYTE1(v26)] ^ dword_AF9400[(unsigned __int8)(v26 >> 16)] ^ dword_AF9800[v26 >> 24];
		
		DWORD v80 = (v20 >> 8) ^ (v79 << 24);
		DWORD v27 = (v25 >> 8) ^ (v20 << 24);
		DWORD v28 = v27 - v23 - 239350324;
		DWORD v29 = v80 + v24 + 239350324;
		
		this->Key[6] = dword_AF8C00[(unsigned __int8)(v80 + BYTE3(v16) + 52)] ^ dword_AF9000[BYTE1(v29)] ^ dword_AF9400[(unsigned __int8)((v80 + v24 + 239350324) >> 16)] ^ dword_AF9800[(v80 + v24 + 239350324) >> 24];
		this->Key[7] = dword_AF8C00[(unsigned __int8)(v27 - BYTE3(v74) - 52)] ^ dword_AF9000[BYTE1(v28)] ^ dword_AF9400[(unsigned __int8)(v28 >> 16)] ^ dword_AF9800[v28 >> 24];
		
		DWORD v30 = (v23 << 8) ^ (v24 >> 24);
		DWORD v31 = (v24 << 8) ^ (v23 >> 24);
		DWORD v32 = v31 + v80 + 478700647;
		
		this->Key[8] = dword_AF8C00[(unsigned __int8)(v31 + v80 + 103)] ^ dword_AF9000[BYTE1(v32)] ^ dword_AF9400[(unsigned __int8)((v31 + v80 + 478700647) >> 16)] ^ dword_AF9800[(v31 + v80 + 478700647) >> 24];
		this->Key[9] = dword_AF8C00[(unsigned __int8)(v27 - v30 - 103)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v27 - v30 - 25703) >> 8)] ^ dword_AF9400[(unsigned __int8)((v27 - v30 - 478700647) >> 16)] ^ dword_AF9800[(v27 - v30 - 478700647) >> 24];
		
		DWORD v33 = ((unsigned __int64)(unsigned int)v80 >> 8) ^ (v27 << 24);
		DWORD v75 = v33;
		DWORD v81 = (v27 >> 8) ^ (v80 << 24);
		DWORD v34 = v31 + v33 + 957401293;
		DWORD v35 = v81 - v30 - 957401293;
		
		this->Key[10] = dword_AF8C00[(unsigned __int8)v34] ^ dword_AF9000[BYTE1(v34)] ^ dword_AF9400[(unsigned __int8)(v34 >> 16)] ^ dword_AF9800[v34 >> 24];
		this->Key[11] = dword_AF8C00[(unsigned __int8)(v81 - v30 + 51)] ^ dword_AF9000[BYTE1(v35)] ^ dword_AF9400[(unsigned __int8)(v35 >> 16)] ^ dword_AF9800[v35 >> 24];
		
		DWORD v36 = ((v31 << 8) ^ (v30 >> 24)) + v75 + 1914802585;
		DWORD v37 = (v31 << 8) ^ (v30 >> 24);
		DWORD v38 = (v30 << 8) ^ (v31 >> 24);
		DWORD v39 = v81 - v38 - 1914802585;
		
		this->Key[12] = dword_AF8C00[(unsigned __int8)(BYTE3(v30) + v75 - 103)] ^ dword_AF9000[BYTE1(v36)] ^ dword_AF9400[(unsigned __int8)(v36 >> 16)] ^ dword_AF9800[v36 >> 24];
		this->Key[13] = dword_AF8C00[(unsigned __int8)(v81 - BYTE3(v31) + 103)] ^ dword_AF9000[BYTE1(v39)] ^ dword_AF9400[(unsigned __int8)(v39 >> 16)] ^ dword_AF9800[v39 >> 24];
		
		DWORD v40 = (v75 >> 8) ^ (v81 << 24);
		DWORD v41 = v40;
		DWORD v42 = v37 - 465362127 + v40;
		DWORD v43 = (v81 >> 8) ^ (v75 << 24);
		DWORD v44 = v43 - v38 + 465362127;
		
		this->Key[14] = dword_AF8C00[(unsigned __int8)v42] ^ dword_AF9000[BYTE1(v42)] ^ dword_AF9400[(unsigned __int8)(v42 >> 16)] ^ dword_AF9800[v42 >> 24];
		this->Key[15] = dword_AF8C00[(unsigned __int8)(BYTE1(v81) - v38 - 49)] ^ dword_AF9000[BYTE1(v44)] ^ dword_AF9400[(unsigned __int8)(v44 >> 16)] ^ dword_AF9800[v44 >> 24];
		
		DWORD v45 = (v37 << 8) ^ (v38 >> 24);
		DWORD v82 = v45;
		DWORD v46 = (v38 << 8) ^ (v37 >> 24);
		DWORD v47 = v41 + v45 - 930724254;
		DWORD v48 = v43 - v46 + 930724254;
		
		this->Key[16] = dword_AF8C00[(unsigned __int8)v47] ^ dword_AF9000[BYTE1(v47)] ^ dword_AF9400[(unsigned __int8)(v47 >> 16)] ^ dword_AF9800[v47 >> 24];
		this->Key[17] = dword_AF8C00[(unsigned __int8)(v43 - v46 - 98)] ^ dword_AF9000[BYTE1(v48)] ^ dword_AF9400[(unsigned __int8)(v48 >> 16)] ^ dword_AF9800[v48 >> 24];
		
		DWORD v49 = ((v41 >> 8) ^ (v43 << 24)) + v82 - 1861448508;
		DWORD v50 = (v43 >> 8) ^ (v41 << 24);
		DWORD v51 = v50 - v46 + 1861448508;
		
		this->Key[18] = dword_AF8C00[(unsigned __int8)(BYTE1(v41) + v82 - 60)] ^ dword_AF9000[BYTE1(v49)] ^ dword_AF9400[(unsigned __int8)(v49 >> 16)] ^ dword_AF9800[v49 >> 24];
		this->Key[19] = dword_AF8C00[(unsigned __int8)(BYTE1(v43) - v46 + 60)] ^ dword_AF9000[BYTE1(v51)] ^ dword_AF9400[(unsigned __int8)(v51 >> 16)] ^ dword_AF9800[v51 >> 24];
		
		DWORD v52 = (v82 << 8) ^ (v46 >> 24);
		DWORD v76 = v52;
		DWORD v53 = (v41 >> 8) ^ (v43 << 24);
		DWORD v83 = (v46 << 8) ^ (v82 >> 24);
		DWORD v54 = v53 + v52 + 572070280;
		DWORD v55 = v50 - v83 - 572070280;
		
		this->Key[20] = dword_AF8C00[(unsigned __int8)v54] ^ dword_AF9000[BYTE1(v54)] ^ dword_AF9400[(unsigned __int8)(v54 >> 16)] ^ dword_AF9800[v54 >> 24];
		this->Key[21] = dword_AF8C00[(unsigned __int8)(v50 - v83 + 120)] ^ dword_AF9000[BYTE1(v55)] ^ dword_AF9400[(unsigned __int8)(v55 >> 16)] ^ dword_AF9800[v55 >> 24];
		
		DWORD v56 = (v53 >> 8) ^ (v50 << 24);
		DWORD v57 = v56 + v76 + 1144140559;
		DWORD v58 = (v53 >> 8) ^ (v50 << 24);
		DWORD v59 = (v50 >> 8) ^ (v53 << 24);
		DWORD v60 = v83;
		DWORD v61 = v59 - v83 - 1144140559;
		
		this->Key[22] = dword_AF8C00[(unsigned __int8)(v56 + v76 + 15)] ^ dword_AF9000[BYTE1(v57)] ^ dword_AF9400[(unsigned __int8)((v56 + v76 + 1144140559) >> 16)] ^ dword_AF9800[(v56 + v76 + 1144140559) >> 24];
		this->Key[23] = dword_AF8C00[(unsigned __int8)(v59 - v83 - 15)] ^ dword_AF9000[BYTE1(v61)] ^ dword_AF9400[(unsigned __int8)(v61 >> 16)] ^ dword_AF9800[v61 >> 24];
		
		DWORD v84 = (v76 << 8) ^ (v83 >> 24);
		DWORD v77 = (v60 << 8) ^ (v76 >> 24);
		DWORD v62 = v59 - v77 + 2006686179;
		
		this->Key[24] = dword_AF8C00[(unsigned __int8)(v84 + v58 + 29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v84 + v58 + 26141) >> 8)] ^ dword_AF9400[(unsigned __int8)((v84 + v58 - 2006686179) >> 16)] ^ dword_AF9800[(v84 + v58 - 2006686179) >> 24];
		this->Key[25] = dword_AF8C00[(unsigned __int8)(v59 - v77 - 29)] ^ dword_AF9000[BYTE1(v62)] ^ dword_AF9400[(unsigned __int8)(v62 >> 16)] ^ dword_AF9800[v62 >> 24];
		
		DWORD v63 = (v59 >> 8) ^ (v58 << 24);
		DWORD v64 = (v58 >> 8) ^ (v59 << 24);
		DWORD v65 = v63;
		DWORD v66 = v63 - v77 - 281594938;
		
		this->Key[26] = dword_AF8C00[(unsigned __int8)(v84 + v64 + 58)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v84 + v64 - 13254) >> 8)] ^ dword_AF9400[(unsigned __int8)((v84 + v64 + 281594938) >> 16)] ^ dword_AF9800[(v84 + v64 + 281594938) >> 24];
		this->Key[27] = dword_AF8C00[(unsigned __int8)v66] ^ dword_AF9000[BYTE1(v66)] ^ dword_AF9400[(unsigned __int8)(v66 >> 16)] ^ dword_AF9800[v66 >> 24];
		
		DWORD v67 = (v84 << 8) ^ (v77 >> 24);
		DWORD v85 = (v77 << 8) ^ (v84 >> 24);
		DWORD v68 = v67 + v64 + 563189875;
		DWORD v69 = v65 - v85 - 563189875;
		
		this->Key[28] = dword_AF8C00[(unsigned __int8)(v67 + v64 + 115)] ^ dword_AF9000[BYTE1(v68)] ^ dword_AF9400[(unsigned __int8)((v67 + v64 + 563189875) >> 16)] ^ dword_AF9800[(v67 + v64 + 563189875) >> 24];
		this->Key[29] = dword_AF8C00[(unsigned __int8)(v65 - v85 - 115)] ^ dword_AF9000[BYTE1(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];
		
		DWORD v70 = v67 + ((v64 >> 8) ^ (v65 << 24)) + 1126379749;
		DWORD v71 = ((v65 >> 8) ^ (v64 << 24)) - v85 - 1126379749;

		this->Key[30] = dword_AF8C00[(unsigned __int8)(v67 + BYTE1(v64) - 27)] ^ dword_AF9000[BYTE1(v70)] ^ dword_AF9400[(unsigned __int8)(v70 >> 16)] ^ dword_AF9800[v70 >> 24];
		this->Key[31] = dword_AF8C00[(unsigned __int8)v71] ^ dword_AF9000[BYTE1(v71)] ^ dword_AF9400[(unsigned __int8)(v71 >> 16)] ^ dword_AF9800[v71 >> 24];
	}
}

// decrypts a block (pilfered from ida)
VOID Cryptor::DecryptBlock(PDWORD pData, PDWORD pBuffer)
{
	// cuts the data block into four byte chuncks
	DWORD v3 = pData[2];
	DWORD v5 = pData[0];
	DWORD v6 = pData[1];
	DWORD v7 = pData[3];
	// decrypts the chuncks
	DWORD v4 = v3;
	v3 = __ROL4__(v3, 8);
	v4 = __ROR4__(v4, 8);
	DWORD v9 = v3 & 0xFF00FF | v4 & 0xFF00FF00;
	DWORD v10 = v7;
	v7 = __ROL4__(v7, 8);
	v10 = __ROR4__(v10, 8);
	DWORD v11 = v9;
	DWORD v12 = v9 ^ this->Key[30];
	DWORD v125 = v7 & 0xFF00FF | v10 & 0xFF00FF00;
	DWORD v13 = v125 ^ v12 ^ this->Key[31];
	DWORD v14 = dword_AF8C00[(unsigned __int8)(v125 ^ v12 ^ (BYTE)this->Key[31])] ^ dword_AF9000[BYTE1(v13)] ^ dword_AF9400[(unsigned __int8)((v125 ^ v12 ^ this->Key[31]) >> 16)] ^ dword_AF9800[(v125 ^ v12 ^ this->Key[31]) >> 24];
	DWORD v15 = v14 + v12;
	DWORD v16 = dword_AF8C00[(unsigned __int8)v15] ^ dword_AF9000[BYTE1(v15)] ^ dword_AF9400[(unsigned __int8)(v15 >> 16)] ^ dword_AF9800[v15 >> 24];
	DWORD v17 = __ROR4__(v5, 8);
	v5 = __ROL4__(v5, 8);
	DWORD v18 = dword_AF8C00[(unsigned __int8)(v16 + v14)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v16 + v14) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v16 + v14) >> 16)] ^ dword_AF9800[(unsigned int)(v16 + v14) >> 24];
	DWORD v19 = (v18 + v16) ^ (v5 & 0xFF00FF | v17 & 0xFF00FF00);
	DWORD v20 = __ROR4__(v6, 8);
	v6 = __ROL4__(v6, 8);
	DWORD v21 = v18 ^ (v6 & 0xFF00FF | v20 & 0xFF00FF00);
	DWORD v22 = v19 ^ this->Key[28];
	DWORD v23 = dword_AF8C00[(unsigned __int8)(v21 ^ v22 ^ (BYTE)this->Key[29])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v21 ^ v22 ^ (WORD)this->Key[29]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v21 ^ v22 ^ this->Key[29]) >> 16)] ^ dword_AF9800[(v21 ^ v22 ^ this->Key[29]) >> 24];
	DWORD v24 = v23 + v22;
	DWORD v25 = dword_AF8C00[(unsigned __int8)v24] ^ dword_AF9000[BYTE1(v24)] ^ dword_AF9400[(unsigned __int8)(v24 >> 16)] ^ dword_AF9800[v24 >> 24];
	DWORD v26 = dword_AF8C00[(unsigned __int8)(v25 + v23)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v25 + v23) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v25 + v23) >> 16)] ^ dword_AF9800[(unsigned int)(v25 + v23) >> 24];
	DWORD v126 = v26 ^ v125;
	DWORD v27 = (v26 + v25) ^ v11;
	DWORD v28 = v27 ^ this->Key[26];
	DWORD v29 = dword_AF8C00[(unsigned __int8)(v126 ^ v28 ^ (BYTE)this->Key[27])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v126 ^ v28 ^ (WORD)this->Key[27]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v126 ^ (unsigned int)v28 ^ this->Key[27]) >> 16)] ^ dword_AF9800[(v126 ^ (unsigned int)v28 ^ this->Key[27]) >> 24];
	DWORD v30 = v29 + v28;
	DWORD v31 = dword_AF8C00[(unsigned __int8)v30] ^ dword_AF9000[BYTE1(v30)] ^ dword_AF9400[(unsigned __int8)(v30 >> 16)] ^ dword_AF9800[v30 >> 24];
	DWORD v32 = dword_AF8C00[(unsigned __int8)(v31 + v29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v31 + v29) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v31 + v29) >> 16)] ^ dword_AF9800[(unsigned int)(v31 + v29) >> 24];
	DWORD v33 = v32 ^ v21;
	DWORD v34 = (v32 + v31) ^ v19;
	DWORD v35 = v34 ^ this->Key[24];
	DWORD v36 = dword_AF8C00[(unsigned __int8)(v33 ^ v35 ^ (BYTE)this->Key[25])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v33 ^ v35 ^ (WORD)this->Key[25]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v33 ^ (unsigned int)v35 ^ this->Key[25]) >> 16)] ^ dword_AF9800[(v33 ^ (unsigned int)v35 ^ this->Key[25]) >> 24];
	DWORD v37 = v36 + v35;
	DWORD v38 = dword_AF8C00[(unsigned __int8)v37] ^ dword_AF9000[BYTE1(v37)] ^ dword_AF9400[(unsigned __int8)(v37 >> 16)] ^ dword_AF9800[v37 >> 24];
	DWORD v39 = dword_AF8C00[(unsigned __int8)(v38 + v36)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v38 + v36) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v38 + v36) >> 16)] ^ dword_AF9800[(unsigned int)(v38 + v36) >> 24];
	DWORD v127 = v39 ^ v126;
	DWORD v40 = (v39 + v38) ^ v27;
	DWORD v41 = v40 ^ this->Key[22];
	DWORD v42 = dword_AF8C00[(unsigned __int8)(v127 ^ v41 ^ (BYTE)this->Key[23])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v127 ^ v41 ^ (WORD)this->Key[23]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v127 ^ (unsigned int)v41 ^ this->Key[23]) >> 16)] ^ dword_AF9800[(v127 ^ (unsigned int)v41 ^ this->Key[23]) >> 24];
	DWORD v43 = v42 + v41;
	DWORD v44 = dword_AF8C00[(unsigned __int8)v43] ^ dword_AF9000[BYTE1(v43)] ^ dword_AF9400[(unsigned __int8)(v43 >> 16)] ^ dword_AF9800[v43 >> 24];
	DWORD v45 = dword_AF8C00[(unsigned __int8)(v44 + v42)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v44 + v42) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v44 + v42) >> 16)] ^ dword_AF9800[(unsigned int)(v44 + v42) >> 24];
	DWORD v46 = v45 ^ v33;
	DWORD v47 = (v45 + v44) ^ v34;
	DWORD v48 = v47 ^ this->Key[20];
	DWORD v49 = dword_AF8C00[(unsigned __int8)(v46 ^ v48 ^ (BYTE)this->Key[21])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v46 ^ v48 ^ (WORD)this->Key[21]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v46 ^ (unsigned int)v48 ^ this->Key[21]) >> 16)] ^ dword_AF9800[(v46 ^ (unsigned int)v48 ^ this->Key[21]) >> 24];
	DWORD v50 = v49 + v48;
	DWORD v51 = dword_AF8C00[(unsigned __int8)v50] ^ dword_AF9000[BYTE1(v50)] ^ dword_AF9400[(unsigned __int8)(v50 >> 16)] ^ dword_AF9800[v50 >> 24];
	DWORD v52 = dword_AF8C00[(unsigned __int8)(v51 + v49)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v51 + v49) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v51 + v49) >> 16)] ^ dword_AF9800[(unsigned int)(v51 + v49) >> 24];
	DWORD v128 = v52 ^ v127;
	DWORD v53 = (v52 + v51) ^ v40;
	DWORD v54 = v53 ^ this->Key[18];
	DWORD v55 = dword_AF8C00[(unsigned __int8)(v128 ^ v54 ^ (BYTE)this->Key[19])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v128 ^ v54 ^ (WORD)this->Key[19]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v128 ^ (unsigned int)v54 ^ this->Key[19]) >> 16)] ^ dword_AF9800[(v128 ^ (unsigned int)v54 ^ this->Key[19]) >> 24];
	DWORD v56 = v55 + v54;
	DWORD v57 = dword_AF8C00[(unsigned __int8)v56] ^ dword_AF9000[BYTE1(v56)] ^ dword_AF9400[(unsigned __int8)(v56 >> 16)] ^ dword_AF9800[v56 >> 24];
	DWORD v58 = dword_AF8C00[(unsigned __int8)(v57 + v55)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v57 + v55) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v57 + v55) >> 16)] ^ dword_AF9800[(unsigned int)(v57 + v55) >> 24];
	DWORD v59 = (v58 + v57) ^ v47;
	DWORD v60 = v58 ^ v46;
	DWORD v61 = v59 ^ this->Key[16];
	DWORD v62 = dword_AF8C00[(unsigned __int8)(v60 ^ v61 ^ (BYTE)this->Key[17])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v60 ^ v61 ^ (WORD)this->Key[17]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v60 ^ (unsigned int)v61 ^ this->Key[17]) >> 16)] ^ dword_AF9800[(v60 ^ (unsigned int)v61 ^ this->Key[17]) >> 24];
	DWORD v63 = v62 + v61;
	DWORD v64 = dword_AF8C00[(unsigned __int8)v63] ^ dword_AF9000[BYTE1(v63)] ^ dword_AF9400[(unsigned __int8)(v63 >> 16)] ^ dword_AF9800[v63 >> 24];
	DWORD v65 = dword_AF8C00[(unsigned __int8)(v64 + v62)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v64 + v62) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v64 + v62) >> 16)] ^ dword_AF9800[(unsigned int)(v64 + v62) >> 24];
	DWORD v129 = v65 ^ v128;
	DWORD v66 = (v65 + v64) ^ v53;
	DWORD v67 = v66 ^ this->Key[14];
	DWORD v68 = dword_AF8C00[(unsigned __int8)(v129 ^ v67 ^ (BYTE)this->Key[15])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v129 ^ v67 ^ (WORD)this->Key[15]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v129 ^ (unsigned int)v67 ^ this->Key[15]) >> 16)] ^ dword_AF9800[(v129 ^ (unsigned int)v67 ^ this->Key[15]) >> 24];
	DWORD v69 = v68 + v67;
	DWORD v70 = dword_AF8C00[(unsigned __int8)v69] ^ dword_AF9000[BYTE1(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];
	DWORD v71 = dword_AF8C00[(unsigned __int8)(v70 + v68)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v70 + v68) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v70 + v68) >> 16)] ^ dword_AF9800[(unsigned int)(v70 + v68) >> 24];
	DWORD v72 = v71 ^ v60;
	DWORD v73 = (v71 + v70) ^ v59;
	DWORD v74 = v73 ^ this->Key[12];
	DWORD v75 = dword_AF8C00[(unsigned __int8)(v72 ^ v74 ^ (BYTE)this->Key[13])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v72 ^ v74 ^ (WORD)this->Key[13]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v72 ^ (unsigned int)v74 ^ this->Key[13]) >> 16)] ^ dword_AF9800[(v72 ^ (unsigned int)v74 ^ this->Key[13]) >> 24];
	DWORD v76 = v75 + v74;
	DWORD v77 = dword_AF8C00[(unsigned __int8)v76] ^ dword_AF9000[BYTE1(v76)] ^ dword_AF9400[(unsigned __int8)(v76 >> 16)] ^ dword_AF9800[v76 >> 24];
	DWORD v78 = dword_AF8C00[(unsigned __int8)(v77 + v75)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v77 + v75) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v77 + v75) >> 16)] ^ dword_AF9800[(unsigned int)(v77 + v75) >> 24];
	DWORD v130 = v78 ^ v129;
	DWORD v79 = (v78 + v77) ^ v66;
	DWORD v80 = v79 ^ this->Key[10];
	DWORD v81 = dword_AF8C00[(unsigned __int8)(v130 ^ v80 ^ (BYTE)this->Key[11])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v130 ^ v80 ^ (WORD)this->Key[11]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v130 ^ (unsigned int)v80 ^ this->Key[11]) >> 16)] ^ dword_AF9800[(v130 ^ (unsigned int)v80 ^ this->Key[11]) >> 24];
	DWORD v82 = v81 + v80;
	DWORD v83 = dword_AF8C00[(unsigned __int8)v82] ^ dword_AF9000[BYTE1(v82)] ^ dword_AF9400[(unsigned __int8)(v82 >> 16)] ^ dword_AF9800[v82 >> 24];
	DWORD v84 = dword_AF8C00[(unsigned __int8)(v83 + v81)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v83 + v81) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v83 + v81) >> 16)] ^ dword_AF9800[(unsigned int)(v83 + v81) >> 24];
	DWORD v85 = v84 ^ v72;
	DWORD v86 = (v84 + v83) ^ v73;
	DWORD v87 = v86 ^ this->Key[8];
	DWORD v88 = dword_AF8C00[(unsigned __int8)(v85 ^ v87 ^ (BYTE)this->Key[9])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v85 ^ v87 ^ (WORD)this->Key[9]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v85 ^ (unsigned int)v87 ^ this->Key[9]) >> 16)] ^ dword_AF9800[(v85 ^ (unsigned int)v87 ^ this->Key[9]) >> 24];
	DWORD v89 = v88 + v87;
	DWORD v90 = dword_AF8C00[(unsigned __int8)v89] ^ dword_AF9000[BYTE1(v89)] ^ dword_AF9400[(unsigned __int8)(v89 >> 16)] ^ dword_AF9800[v89 >> 24];
	DWORD v91 = dword_AF8C00[(unsigned __int8)(v90 + v88)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v90 + v88) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v90 + v88) >> 16)] ^ dword_AF9800[(unsigned int)(v90 + v88) >> 24];
	DWORD v131 = v91 ^ v130;
	DWORD v92 = (v91 + v90) ^ v79;
	DWORD v93 = v92 ^ this->Key[6];
	DWORD v94 = dword_AF8C00[(unsigned __int8)(v131 ^ v93 ^ (BYTE)this->Key[7])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v131 ^ v93 ^ (WORD)this->Key[7]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v131 ^ (unsigned int)v93 ^ this->Key[7]) >> 16)] ^ dword_AF9800[(v131 ^ (unsigned int)v93 ^ this->Key[7]) >> 24];
	DWORD v95 = v94 + v93;
	DWORD v96 = dword_AF8C00[(unsigned __int8)v95] ^ dword_AF9000[BYTE1(v95)] ^ dword_AF9400[(unsigned __int8)(v95 >> 16)] ^ dword_AF9800[v95 >> 24];
	DWORD v97 = dword_AF8C00[(unsigned __int8)(v96 + v94)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v96 + v94) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v96 + v94) >> 16)] ^ dword_AF9800[(unsigned int)(v96 + v94) >> 24];
	DWORD v98 = v97 ^ v85;
	DWORD v99 = (v97 + v96) ^ v86;
	DWORD v100 = v99 ^ this->Key[4];
	DWORD v101 = dword_AF8C00[(unsigned __int8)(v98 ^ v100 ^ (BYTE)this->Key[5])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v98 ^ v100 ^ (WORD)this->Key[5]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v98 ^ (unsigned int)v100 ^ this->Key[5]) >> 16)] ^ dword_AF9800[(v98 ^ (unsigned int)v100 ^ this->Key[5]) >> 24];
	DWORD v102 = v101 + v100;
	DWORD v103 = dword_AF8C00[(unsigned __int8)v102] ^ dword_AF9000[BYTE1(v102)] ^ dword_AF9400[(unsigned __int8)(v102 >> 16)] ^ dword_AF9800[v102 >> 24];
	DWORD v104 = dword_AF8C00[(unsigned __int8)(v103 + v101)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v103 + v101) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v103 + v101) >> 16)] ^ dword_AF9800[(unsigned int)(v103 + v101) >> 24];
	DWORD v132 = v104 ^ v131;
	DWORD v105 = (v104 + v103) ^ v92;
	DWORD v106 = v105 ^ this->Key[2];
	DWORD v107 = dword_AF8C00[(unsigned __int8)(v132 ^ v106 ^ (BYTE)this->Key[3])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v132 ^ v106 ^ (WORD)this->Key[3]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v132 ^ (unsigned int)v106 ^ this->Key[3]) >> 16)] ^ dword_AF9800[(v132 ^ (unsigned int)v106 ^ this->Key[3]) >> 24];
	DWORD v108 = v107 + v106;
	DWORD v109 = dword_AF8C00[(unsigned __int8)v108] ^ dword_AF9000[BYTE1(v108)] ^ dword_AF9400[(unsigned __int8)(v108 >> 16)] ^ dword_AF9800[v108 >> 24];
	DWORD v110 = dword_AF8C00[(unsigned __int8)(v109 + v107)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v109 + v107) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v109 + v107) >> 16)] ^ dword_AF9800[(unsigned int)(v109 + v107) >> 24];
	DWORD v111 = v110 ^ v98;
	DWORD v112 = (v110 + v109) ^ v99;
	DWORD v113 = v112 ^ this->Key[0];
	DWORD v114 = dword_AF8C00[(unsigned __int8)(v111 ^ v113 ^ (BYTE)this->Key[1])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v111 ^ v113 ^ (WORD)this->Key[1]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v111 ^ (unsigned int)v113 ^ this->Key[1]) >> 16)] ^ dword_AF9800[(v111 ^ (unsigned int)v113 ^ this->Key[1]) >> 24];
	DWORD v115 = v114 + v113;
	DWORD v116 = dword_AF8C00[(unsigned __int8)v115] ^ dword_AF9000[BYTE1(v115)] ^ dword_AF9400[(unsigned __int8)(v115 >> 16)] ^ dword_AF9800[v115 >> 24];
	DWORD v117 = dword_AF8C00[(unsigned __int8)(v116 + v114)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v116 + v114) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v116 + v114) >> 16)] ^ dword_AF9800[(unsigned int)(v116 + v114) >> 24];
	DWORD v118 = (v117 + v116) ^ v105;
	DWORD v119 = v118;
	v118 = __ROL4__(v118, 8);
	v119 = __ROR4__(v119, 8);
	DWORD v120 = __ROR4__(v117 ^ v132, 8);
	DWORD v121 = __ROL4__(v117 ^ v132, 8);
	DWORD v122 = __ROR4__(v112, 8);
	v112 = __ROL4__(v112, 8);
	DWORD v123 = v111;
	v111 = __ROL4__(v111, 8);
	v123 = __ROR4__(v123, 8);
	// adds the decrypted chuncks to the block of the output buffer
	pBuffer[0] = v118 & 0xFF00FF | v119 & 0xFF00FF00;
	pBuffer[1] = v121 & 0xFF00FF | v120 & 0xFF00FF00;
	pBuffer[2] = v112 & 0xFF00FF | v122 & 0xFF00FF00;
	pBuffer[3] = v111 & 0xFF00FF | v123 & 0xFF00FF00;
}

// decrypts the given data buffer
BOOL Cryptor::Decrypt(PDWORD pData, DWORD dwSize, PDWORD pBuffer)
{
	// validates the arguments
	if (pData && pBuffer && dwSize >= 16)
	{
		// stores the first decryption block
		PDWORD pFirst = (PDWORD)&Block;
		// iterates through the 16 byte blocks
		for (DWORD dwBlocks = dwSize / 16; dwBlocks != 0; dwBlocks--)
		{
			// decrypts the block
			DecryptBlock(pData, pBuffer);
			// xors with the previous block
			pBuffer[0] ^= pFirst[0];
			pBuffer[1] ^= pFirst[1];
			pBuffer[2] ^= pFirst[2];
			pBuffer[3] ^= pFirst[3];
			// sets the block pointer as a pointer to the new block
			pFirst = pData;
			// gets the next block
			pData += 4;
			// gets the next block
			pBuffer += 4;
		}
		// function succeeded
		return TRUE;
	}
	// function failed
	return NULL;
}

VOID Cryptor::EncryptBlock(PDWORD pData, PDWORD pBuffer)
{
	int v3; // edx@1
	int v4; // ebx@1
	int v5; // esi@1
	int v6; // edi@1
	int v7; // eax@1
	// int v8; // ST10_4@1
	unsigned int v9; // ebx@1
	int v10; // edx@1
	unsigned int v11; // ST14_4@1
	int v12; // ebx@1
	int v13; // edx@1
	int v14; // ecx@1
	unsigned int v15; // ebx@1
	int v16; // edx@1
	int v17; // ebx@1
	int v18; // ecx@1
	unsigned int v19; // ST0C_4@1
	int v20; // esi@1
	unsigned int v21; // esi@1
	int v22; // ebx@1
	int v23; // ecx@1
	unsigned int v24; // ebx@1
	int v25; // edx@1
	int v26; // ecx@1
	int v27; // ST14_4@1
	int v28; // ebx@1
	int v29; // ecx@1
	unsigned int v30; // ebx@1
	int v31; // edx@1
	int v32; // ecx@1
	int v33; // esi@1
	int v34; // edi@1
	int v35; // ebx@1
	int v36; // ecx@1
	unsigned int v37; // ebx@1
	int v38; // edx@1
	int v39; // ecx@1
	int v40; // ST14_4@1
	int v41; // ebx@1
	int v42; // ecx@1
	unsigned int v43; // ebx@1
	int v44; // edx@1
	int v45; // ecx@1
	int v46; // esi@1
	int v47; // edi@1
	int v48; // ebx@1
	int v49; // ecx@1
	unsigned int v50; // ebx@1
	int v51; // edx@1
	int v52; // ecx@1
	int v53; // ST14_4@1
	int v54; // ebx@1
	int v55; // ecx@1
	unsigned int v56; // ebx@1
	int v57; // edx@1
	int v58; // ecx@1
	int v59; // edi@1
	int v60; // esi@1
	int v61; // ebx@1
	int v62; // ecx@1
	unsigned int v63; // ebx@1
	int v64; // edx@1
	int v65; // ecx@1
	int v66; // ST14_4@1
	int v67; // ebx@1
	int v68; // ecx@1
	unsigned int v69; // ebx@1
	int v70; // edx@1
	int v71; // ecx@1
	int v72; // esi@1
	int v73; // edi@1
	int v74; // ebx@1
	int v75; // ecx@1
	unsigned int v76; // ebx@1
	int v77; // edx@1
	int v78; // ecx@1
	int v79; // ST14_4@1
	int v80; // ebx@1
	int v81; // ecx@1
	unsigned int v82; // ebx@1
	int v83; // edx@1
	int v84; // ecx@1
	int v85; // esi@1
	int v86; // edi@1
	int v87; // ebx@1
	int v88; // ecx@1
	unsigned int v89; // ebx@1
	int v90; // edx@1
	int v91; // ecx@1
	int v92; // ST14_4@1
	int v93; // ebx@1
	int v94; // ecx@1
	unsigned int v95; // ebx@1
	int v96; // edx@1
	int v97; // ecx@1
	int v98; // esi@1
	int v99; // edi@1
	int v100; // ebx@1
	int v101; // ecx@1
	unsigned int v102; // ebx@1
	int v103; // edx@1
	int v104; // ecx@1
	int v105; // ST14_4@1
	int v106; // ebx@1
	int v107; // ecx@1
	unsigned int v108; // ebx@1
	int v109; // edx@1
	int v110; // ecx@1
	int v111; // esi@1
	int v112; // edi@1
	int v113; // ebx@1
	int v114; // ecx@1
	unsigned int v115; // ebx@1
	int v116; // edx@1
	int v117; // ecx@1
	int v118; // edx@1
	int v119; // eax@1
	int v120; // eax@1
	int v121; // ebx@1
	int v122; // eax@1
	int v123; // eax@1
	unsigned int result; // eax@1
	unsigned int v125; // [sp+20h] [bp+8h]@1
	int v126; // [sp+20h] [bp+8h]@1
	int v127; // [sp+20h] [bp+8h]@1
	int v128; // [sp+20h] [bp+8h]@1
	int v129; // [sp+20h] [bp+8h]@1
	int v130; // [sp+20h] [bp+8h]@1
	int v131; // [sp+20h] [bp+8h]@1
	int v132; // [sp+20h] [bp+8h]@1

	v5 = pData[0];
	v6 = pData[1];
	v3 = pData[2];
	v7 = pData[3];

	v4 = v3;
	v3 = __ROL4__(v3, 8);
	v4 = __ROR4__(v4, 8);
	v9 = v3 & 0xFF00FF | v4 & 0xFF00FF00;
	v10 = v7;
	v7 = __ROL4__(v7, 8);
	v10 = __ROR4__(v10, 8);
	v11 = v9;
	v12 = v9 ^ this->Key[0];
	v125 = v7 & 0xFF00FF | v10 & 0xFF00FF00;
	v13 = v125 ^ v12 ^ this->Key[1];
	v14 = dword_AF8C00[(unsigned __int8)(v125 ^ v12 ^ (BYTE)this->Key[1])] ^ dword_AF9000[BYTE1(v13)] ^ dword_AF9400[(unsigned __int8)((v125 ^ v12 ^ this->Key[1]) >> 16)] ^ dword_AF9800[(v125 ^ v12 ^ this->Key[1]) >> 24];
	v15 = v14 + v12;
	v16 = dword_AF8C00[(unsigned __int8)v15] ^ dword_AF9000[BYTE1(v15)] ^ dword_AF9400[(unsigned __int8)(v15 >> 16)] ^ dword_AF9800[v15 >> 24];
	v17 = __ROR4__(v5, 8);
	v5 = __ROL4__(v5, 8);
	v18 = dword_AF8C00[(unsigned __int8)(v16 + v14)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v16 + v14) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v16 + v14) >> 16)] ^ dword_AF9800[(unsigned int)(v16 + v14) >> 24];
	v19 = (v18 + v16) ^ (v5 & 0xFF00FF | v17 & 0xFF00FF00);
	v20 = __ROR4__(v6, 8);
	v6 = __ROL4__(v6, 8);
	v21 = v18 ^ (v6 & 0xFF00FF | v20 & 0xFF00FF00);
	v22 = v19 ^ this->Key[2];
	v23 = dword_AF8C00[(unsigned __int8)(v21 ^ v22 ^ (BYTE)this->Key[3])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v21 ^ v22 ^ (WORD)this->Key[3]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v21 ^ v22 ^ this->Key[3]) >> 16)] ^ dword_AF9800[(v21 ^ v22 ^ this->Key[3]) >> 24];
	v24 = v23 + v22;
	v25 = dword_AF8C00[(unsigned __int8)v24] ^ dword_AF9000[BYTE1(v24)] ^ dword_AF9400[(unsigned __int8)(v24 >> 16)] ^ dword_AF9800[v24 >> 24];
	v26 = dword_AF8C00[(unsigned __int8)(v25 + v23)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v25 + v23) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v25 + v23) >> 16)] ^ dword_AF9800[(unsigned int)(v25 + v23) >> 24];
	v126 = v26 ^ v125;
	v27 = (v26 + v25) ^ v11;
	v28 = v27 ^ this->Key[4];
	v29 = dword_AF8C00[(unsigned __int8)(v126 ^ v28 ^ (BYTE)this->Key[5])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v126 ^ v28 ^ (WORD)this->Key[5]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v126 ^ (unsigned int)v28 ^ this->Key[5]) >> 16)] ^ dword_AF9800[(v126 ^ (unsigned int)v28 ^ this->Key[5]) >> 24];
	v30 = v29 + v28;
	v31 = dword_AF8C00[(unsigned __int8)v30] ^ dword_AF9000[BYTE1(v30)] ^ dword_AF9400[(unsigned __int8)(v30 >> 16)] ^ dword_AF9800[v30 >> 24];
	v32 = dword_AF8C00[(unsigned __int8)(v31 + v29)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v31 + v29) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v31 + v29) >> 16)] ^ dword_AF9800[(unsigned int)(v31 + v29) >> 24];
	v33 = v32 ^ v21;
	v34 = (v32 + v31) ^ v19;
	v35 = v34 ^ this->Key[6];
	v36 = dword_AF8C00[(unsigned __int8)(v33 ^ v35 ^ (BYTE)this->Key[7])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v33 ^ v35 ^ (WORD)this->Key[7]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v33 ^ (unsigned int)v35 ^ this->Key[7]) >> 16)] ^ dword_AF9800[(v33 ^ (unsigned int)v35 ^ this->Key[7]) >> 24];
	v37 = v36 + v35;
	v38 = dword_AF8C00[(unsigned __int8)v37] ^ dword_AF9000[BYTE1(v37)] ^ dword_AF9400[(unsigned __int8)(v37 >> 16)] ^ dword_AF9800[v37 >> 24];
	v39 = dword_AF8C00[(unsigned __int8)(v38 + v36)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v38 + v36) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v38 + v36) >> 16)] ^ dword_AF9800[(unsigned int)(v38 + v36) >> 24];
	v127 = v39 ^ v126;
	v40 = (v39 + v38) ^ v27;
	v41 = v40 ^ this->Key[8];
	v42 = dword_AF8C00[(unsigned __int8)(v127 ^ v41 ^ (BYTE)this->Key[9])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v127 ^ v41 ^ (WORD)this->Key[9]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v127 ^ (unsigned int)v41 ^ this->Key[9]) >> 16)] ^ dword_AF9800[(v127 ^ (unsigned int)v41 ^ this->Key[9]) >> 24];
	v43 = v42 + v41;
	v44 = dword_AF8C00[(unsigned __int8)v43] ^ dword_AF9000[BYTE1(v43)] ^ dword_AF9400[(unsigned __int8)(v43 >> 16)] ^ dword_AF9800[v43 >> 24];
	v45 = dword_AF8C00[(unsigned __int8)(v44 + v42)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v44 + v42) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v44 + v42) >> 16)] ^ dword_AF9800[(unsigned int)(v44 + v42) >> 24];
	v46 = v45 ^ v33;
	v47 = (v45 + v44) ^ v34;
	v48 = v47 ^ this->Key[10];
	v49 = dword_AF8C00[(unsigned __int8)(v46 ^ v48 ^ (BYTE)this->Key[11])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v46 ^ v48 ^ (WORD)this->Key[11]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v46 ^ (unsigned int)v48 ^ this->Key[11]) >> 16)] ^ dword_AF9800[(v46 ^ (unsigned int)v48 ^ this->Key[11]) >> 24];
	v50 = v49 + v48;
	v51 = dword_AF8C00[(unsigned __int8)v50] ^ dword_AF9000[BYTE1(v50)] ^ dword_AF9400[(unsigned __int8)(v50 >> 16)] ^ dword_AF9800[v50 >> 24];
	v52 = dword_AF8C00[(unsigned __int8)(v51 + v49)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v51 + v49) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v51 + v49) >> 16)] ^ dword_AF9800[(unsigned int)(v51 + v49) >> 24];
	v128 = v52 ^ v127;
	v53 = (v52 + v51) ^ v40;
	v54 = v53 ^ this->Key[12];
	v55 = dword_AF8C00[(unsigned __int8)(v128 ^ v54 ^ (BYTE)this->Key[13])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v128 ^ v54 ^ (WORD)this->Key[13]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v128 ^ (unsigned int)v54 ^ this->Key[13]) >> 16)] ^ dword_AF9800[(v128 ^ (unsigned int)v54 ^ this->Key[13]) >> 24];
	v56 = v55 + v54;
	v57 = dword_AF8C00[(unsigned __int8)v56] ^ dword_AF9000[BYTE1(v56)] ^ dword_AF9400[(unsigned __int8)(v56 >> 16)] ^ dword_AF9800[v56 >> 24];
	v58 = dword_AF8C00[(unsigned __int8)(v57 + v55)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v57 + v55) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v57 + v55) >> 16)] ^ dword_AF9800[(unsigned int)(v57 + v55) >> 24];
	v59 = (v58 + v57) ^ v47;
	v60 = v58 ^ v46;
	v61 = v59 ^ this->Key[14];
	v62 = dword_AF8C00[(unsigned __int8)(v60 ^ v61 ^ (BYTE)this->Key[15])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v60 ^ v61 ^ (WORD)this->Key[15]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v60 ^ (unsigned int)v61 ^ this->Key[15]) >> 16)] ^ dword_AF9800[(v60 ^ (unsigned int)v61 ^ this->Key[15]) >> 24];
	v63 = v62 + v61;
	v64 = dword_AF8C00[(unsigned __int8)v63] ^ dword_AF9000[BYTE1(v63)] ^ dword_AF9400[(unsigned __int8)(v63 >> 16)] ^ dword_AF9800[v63 >> 24];
	v65 = dword_AF8C00[(unsigned __int8)(v64 + v62)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v64 + v62) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v64 + v62) >> 16)] ^ dword_AF9800[(unsigned int)(v64 + v62) >> 24];
	v129 = v65 ^ v128;
	v66 = (v65 + v64) ^ v53;
	v67 = v66 ^ this->Key[16];
	v68 = dword_AF8C00[(unsigned __int8)(v129 ^ v67 ^ (BYTE)this->Key[17])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v129 ^ v67 ^ (WORD)this->Key[17]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v129 ^ (unsigned int)v67 ^ this->Key[17]) >> 16)] ^ dword_AF9800[(v129 ^ (unsigned int)v67 ^ this->Key[17]) >> 24];
	v69 = v68 + v67;
	v70 = dword_AF8C00[(unsigned __int8)v69] ^ dword_AF9000[BYTE1(v69)] ^ dword_AF9400[(unsigned __int8)(v69 >> 16)] ^ dword_AF9800[v69 >> 24];
	v71 = dword_AF8C00[(unsigned __int8)(v70 + v68)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v70 + v68) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v70 + v68) >> 16)] ^ dword_AF9800[(unsigned int)(v70 + v68) >> 24];
	v72 = v71 ^ v60;
	v73 = (v71 + v70) ^ v59;
	v74 = v73 ^ this->Key[18];
	v75 = dword_AF8C00[(unsigned __int8)(v72 ^ v74 ^ (BYTE)this->Key[19])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v72 ^ v74 ^ (WORD)this->Key[19]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v72 ^ (unsigned int)v74 ^ this->Key[19]) >> 16)] ^ dword_AF9800[(v72 ^ (unsigned int)v74 ^ this->Key[19]) >> 24];
	v76 = v75 + v74;
	v77 = dword_AF8C00[(unsigned __int8)v76] ^ dword_AF9000[BYTE1(v76)] ^ dword_AF9400[(unsigned __int8)(v76 >> 16)] ^ dword_AF9800[v76 >> 24];
	v78 = dword_AF8C00[(unsigned __int8)(v77 + v75)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v77 + v75) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v77 + v75) >> 16)] ^ dword_AF9800[(unsigned int)(v77 + v75) >> 24];
	v130 = v78 ^ v129;
	v79 = (v78 + v77) ^ v66;
	v80 = v79 ^ this->Key[20];
	v81 = dword_AF8C00[(unsigned __int8)(v130 ^ v80 ^ (BYTE)this->Key[21])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v130 ^ v80 ^ (WORD)this->Key[21]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v130 ^ (unsigned int)v80 ^ this->Key[21]) >> 16)] ^ dword_AF9800[(v130 ^ (unsigned int)v80 ^ this->Key[21]) >> 24];
	v82 = v81 + v80;
	v83 = dword_AF8C00[(unsigned __int8)v82] ^ dword_AF9000[BYTE1(v82)] ^ dword_AF9400[(unsigned __int8)(v82 >> 16)] ^ dword_AF9800[v82 >> 24];
	v84 = dword_AF8C00[(unsigned __int8)(v83 + v81)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v83 + v81) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v83 + v81) >> 16)] ^ dword_AF9800[(unsigned int)(v83 + v81) >> 24];
	v85 = v84 ^ v72;
	v86 = (v84 + v83) ^ v73;
	v87 = v86 ^ this->Key[22];
	v88 = dword_AF8C00[(unsigned __int8)(v85 ^ v87 ^ (BYTE)this->Key[23])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v85 ^ v87 ^ (WORD)this->Key[23]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v85 ^ (unsigned int)v87 ^ this->Key[23]) >> 16)] ^ dword_AF9800[(v85 ^ (unsigned int)v87 ^ this->Key[23]) >> 24];
	v89 = v88 + v87;
	v90 = dword_AF8C00[(unsigned __int8)v89] ^ dword_AF9000[BYTE1(v89)] ^ dword_AF9400[(unsigned __int8)(v89 >> 16)] ^ dword_AF9800[v89 >> 24];
	v91 = dword_AF8C00[(unsigned __int8)(v90 + v88)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v90 + v88) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v90 + v88) >> 16)] ^ dword_AF9800[(unsigned int)(v90 + v88) >> 24];
	v131 = v91 ^ v130;
	v92 = (v91 + v90) ^ v79;
	v93 = v92 ^ this->Key[24];
	v94 = dword_AF8C00[(unsigned __int8)(v131 ^ v93 ^ (BYTE)this->Key[25])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v131 ^ v93 ^ (WORD)this->Key[25]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v131 ^ (unsigned int)v93 ^ this->Key[25]) >> 16)] ^ dword_AF9800[(v131 ^ (unsigned int)v93 ^ this->Key[25]) >> 24];
	v95 = v94 + v93;
	v96 = dword_AF8C00[(unsigned __int8)v95] ^ dword_AF9000[BYTE1(v95)] ^ dword_AF9400[(unsigned __int8)(v95 >> 16)] ^ dword_AF9800[v95 >> 24];
	v97 = dword_AF8C00[(unsigned __int8)(v96 + v94)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v96 + v94) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v96 + v94) >> 16)] ^ dword_AF9800[(unsigned int)(v96 + v94) >> 24];
	v98 = v97 ^ v85;
	v99 = (v97 + v96) ^ v86;
	v100 = v99 ^ this->Key[26];
	v101 = dword_AF8C00[(unsigned __int8)(v98 ^ v100 ^ (BYTE)this->Key[27])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v98 ^ v100 ^ (WORD)this->Key[27]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v98 ^ (unsigned int)v100 ^ this->Key[27]) >> 16)] ^ dword_AF9800[(v98 ^ (unsigned int)v100 ^ this->Key[27]) >> 24];
	v102 = v101 + v100;
	v103 = dword_AF8C00[(unsigned __int8)v102] ^ dword_AF9000[BYTE1(v102)] ^ dword_AF9400[(unsigned __int8)(v102 >> 16)] ^ dword_AF9800[v102 >> 24];
	v104 = dword_AF8C00[(unsigned __int8)(v103 + v101)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v103 + v101) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v103 + v101) >> 16)] ^ dword_AF9800[(unsigned int)(v103 + v101) >> 24];
	v132 = v104 ^ v131;
	v105 = (v104 + v103) ^ v92;
	v106 = v105 ^ this->Key[28];
	v107 = dword_AF8C00[(unsigned __int8)(v132 ^ v106 ^ (BYTE)this->Key[29])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v132 ^ v106 ^ (WORD)this->Key[29]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v132 ^ (unsigned int)v106 ^ this->Key[29]) >> 16)] ^ dword_AF9800[(v132 ^ (unsigned int)v106 ^ this->Key[29]) >> 24];
	v108 = v107 + v106;
	v109 = dword_AF8C00[(unsigned __int8)v108] ^ dword_AF9000[BYTE1(v108)] ^ dword_AF9400[(unsigned __int8)(v108 >> 16)] ^ dword_AF9800[v108 >> 24];
	v110 = dword_AF8C00[(unsigned __int8)(v109 + v107)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v109 + v107) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v109 + v107) >> 16)] ^ dword_AF9800[(unsigned int)(v109 + v107) >> 24];
	v111 = v110 ^ v98;
	v112 = (v110 + v109) ^ v99;
	v113 = v112 ^ this->Key[30];
	v114 = dword_AF8C00[(unsigned __int8)(v111 ^ v113 ^ (BYTE)this->Key[31])] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v111 ^ v113 ^ (WORD)this->Key[31]) >> 8)] ^ dword_AF9400[(unsigned __int8)((v111 ^ (unsigned int)v113 ^ this->Key[31]) >> 16)] ^ dword_AF9800[(v111 ^ (unsigned int)v113 ^ this->Key[31]) >> 24];
	v115 = v114 + v113;
	v116 = dword_AF8C00[(unsigned __int8)v115] ^ dword_AF9000[BYTE1(v115)] ^ dword_AF9400[(unsigned __int8)(v115 >> 16)] ^ dword_AF9800[v115 >> 24];
	v117 = dword_AF8C00[(unsigned __int8)(v116 + v114)] ^ dword_AF9000[(unsigned __int8)((unsigned __int16)(v116 + v114) >> 8)] ^ dword_AF9400[(unsigned __int8)((unsigned int)(v116 + v114) >> 16)] ^ dword_AF9800[(unsigned int)(v116 + v114) >> 24];
	v118 = (v117 + v116) ^ v105;
	v119 = v118;
	v118 = __ROL4__(v118, 8);
	v119 = __ROR4__(v119, 8);
	v120 = __ROR4__(v117 ^ v132, 8);
	v121 = __ROL4__(v117 ^ v132, 8);
	v122 = __ROR4__(v112, 8);
	v112 = __ROL4__(v112, 8);
	v123 = v111;
	v111 = __ROL4__(v111, 8);
	v123 = __ROR4__(v123, 8);

	pBuffer[0] = v118 & 0xFF00FF | v119 & 0xFF00FF00;
	pBuffer[1] = v121 & 0xFF00FF | v120 & 0xFF00FF00;
	pBuffer[2] = v112 & 0xFF00FF | v122 & 0xFF00FF00;
	pBuffer[3] = v111 & 0xFF00FF | v123 & 0xFF00FF00;
}

// encrypts the given data buffer
BOOL Cryptor::Encrypt(PDWORD pData, DWORD dwSize, PDWORD pBuffer)
{
	// validates the arguments
	if (pData && pBuffer && dwSize >= 16)
	{
		// stores the first encryption block
		PDWORD pFirst = (PDWORD)&Block;
		// iterates through the 16 byte blocks
		for (DWORD dwBlocks = dwSize / 16; dwBlocks != 0; dwBlocks--)
		{
			// xors with the previous block
			pBuffer[0] = pData[0] ^ pFirst[0];
			pBuffer[1] = pData[1] ^ pFirst[1];
			pBuffer[2] = pData[2] ^ pFirst[2];
			pBuffer[3] = pData[3] ^ pFirst[3];
			// decrypts the block
			EncryptBlock(pBuffer, pBuffer);
			// sets the block pointer as a pointer to the new block
			pFirst = pBuffer;
			// gets the next block
			pData += 4;
			// gets the next block
			pBuffer += 4;
		}
		// function succeeded
		return TRUE;
	}
	// function failed
	return NULL;
}