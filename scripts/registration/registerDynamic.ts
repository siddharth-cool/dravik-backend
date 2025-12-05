import { SPGNFTContractAddress } from "../../utils/utils";
import { client, networkInfo } from "../../utils/config";
import { uploadJSONToIPFS } from "../../utils/functions/uploadToIpfs";
import { createHash } from "crypto";
import {
  IpMetadata,
  LicenseTerms,
  WIP_TOKEN_ADDRESS,
} from "@story-protocol/core-sdk";
import axios from "axios";
import FormData from "form-data";
import { getAddress } from "viem";

interface RegisterInput {
  metadata: {
    title: string;
    description: string;
    creatorName: string;
    creatorWallet: string;
  };
  licenseOptions: {
    commercialAllowed: boolean;
    remixAllowed: boolean;
    aiTrainingAllowed: boolean;  // Custom field only for NFT metadata
    revShare: number;
    maxLicenses: number;
  };
  imageFile?: any;
  mediaFile?: any;
}

async function uploadBufferToIPFS(buffer: Buffer, filename: string) {
  const url = "https://api.pinata.cloud/pinning/pinFileToIPFS";
  const data = new FormData();
  data.append("file", buffer, { filename });

  const res = await axios.post(url, data, {
    maxContentLength: Infinity,
    headers: {
      Authorization: `Bearer ${process.env.PINATA_JWT}`,
      ...data.getHeaders(),
    },
  });

  return res.data.IpfsHash;
}

// Story Protocol_LICENSE TERMS (ONLY allowed fields)
function buildLicenseTerms(opts: any): LicenseTerms {
  const commercialEnabled = opts.commercialAllowed;

  const royaltyPolicyAddress = commercialEnabled
  ? "0xBe54FB168b3c982b7AaE60dB6CF75Bd8447b390E"
  : "0x0000000000000000000000000000000000000000";

  const currencyAddress = commercialEnabled
    ? WIP_TOKEN_ADDRESS
    : "0x0000000000000000000000000000000000000000";

  const revShare = commercialEnabled ? Number(opts.revShare || 0) : 0;

  return {
    commercialUse: commercialEnabled,
    derivativesAllowed: opts.remixAllowed,

    commercialAttribution: false,
    derivativesAttribution: false,

    derivativesApproval: false,
    derivativesReciprocal: false,

    commercializerChecker: "0x0000000000000000000000000000000000000000",
    commercializerCheckerData: "0x",

    commercialRevShare: revShare,
    commercialRevCeiling: 0n,
    derivativeRevCeiling: 0n,

    transferable: true,

    currency: currencyAddress,
    defaultMintingFee: 0n,
    expiration: 0n,

    royaltyPolicy: royaltyPolicyAddress,

    uri: "",
  };
}



export async function registerDynamicAsset({
  metadata,
  licenseOptions,
  imageFile,
  mediaFile,
}: RegisterInput) {
  const imageHash = imageFile
    ? await uploadBufferToIPFS(imageFile.buffer, imageFile.originalname)
    : null;

  const mediaHash = mediaFile
    ? await uploadBufferToIPFS(mediaFile.buffer, mediaFile.originalname)
    : null;

  const imageUrl = imageHash ? `https://ipfs.io/ipfs/${imageHash}` : undefined;
  const mediaUrl = mediaHash ? `https://ipfs.io/ipfs/${mediaHash}` : undefined;

  const ipMetadata: IpMetadata = client.ipAsset.generateIpMetadata({
    title: metadata.title,
    description: metadata.description,
    createdAt: `${Math.floor(Date.now() / 1000)}`,

    creators: [
      {
        name: metadata.creatorName,
        address: metadata.creatorWallet as `0x${string}`,
        contributionPercent: 100,
      },
    ],

    image: imageUrl,
    imageHash: imageHash
      ? `0x${createHash("sha256").update(imageHash).digest("hex")}`
      : undefined,

    mediaUrl,
    mediaHash: mediaHash
      ? `0x${createHash("sha256").update(mediaHash).digest("hex")}`
      : undefined,
    mediaType: mediaFile?.mimetype,
  });

  const nftMetadata = {
    name: metadata.title,
    description: metadata.description,
    image: imageUrl,
    animation_url: mediaUrl,
    attributes: [
      { key: "Creator", value: metadata.creatorName },
      { key: "Wallet", value: metadata.creatorWallet },
      { key: "Commercial Allowed", value: licenseOptions.commercialAllowed },
      { key: "Remix Allowed", value: licenseOptions.remixAllowed },
      { key: "AI Training Allowed", value: licenseOptions.aiTrainingAllowed },
      { key: "Royalty (%)", value: licenseOptions.revShare },
      { key: "Max Licenses", value: licenseOptions.maxLicenses },
    ],
  };

  const ipIpfsHash = await uploadJSONToIPFS(ipMetadata);
  const nftIpfsHash = await uploadJSONToIPFS(nftMetadata);

  const ipHash = createHash("sha256")
    .update(JSON.stringify(ipMetadata))
    .digest("hex");

  const nftHash = createHash("sha256")
    .update(JSON.stringify(nftMetadata))
    .digest("hex");

  const response = await client.ipAsset.registerIpAsset({
    nft: {
      type: "mint",
      spgNftContract: SPGNFTContractAddress,
    },

    licenseTermsData: [
      {
        terms: buildLicenseTerms(licenseOptions),
        maxLicenseTokens: licenseOptions.maxLicenses,
      },
    ],

    ipMetadata: {
      ipMetadataURI: `https://ipfs.io/ipfs/${ipIpfsHash}`,
      ipMetadataHash: `0x${ipHash}`,
      nftMetadataURI: `https://ipfs.io/ipfs/${nftIpfsHash}`,
      nftMetadataHash: `0x${nftHash}`,
    },
  });
const terms = buildLicenseTerms(licenseOptions);

return {
  txHash: response.txHash,
  ipId: response.ipId,
  licenseTermsIds: (response.licenseTermsIds ?? []).map((id: bigint) => id.toString()),
  licenseTerms: [
    {
      ...terms,
      licenseTermsId: (response.licenseTermsIds ?? [])[0]?.toString() || null, // attach ID
      aiTraining: licenseOptions.aiTrainingAllowed, // include this explicitly
      maxLicenses: licenseOptions.maxLicenses,
    }
  ],
  imageUrl,
  mediaUrl,
  explorer: `${networkInfo.protocolExplorer}/ipa/${response.ipId}`,
};

}

