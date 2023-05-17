import {
  Cbor,
  Certificate,
  // HashTree,
  // HttpAgent,
  lookup_path,
  reconstruct,
  compare
} from "@dfinity/agent";
// import { Principal } from "@dfinity/principal";
// import { lebDecode } from "@dfinity/candid";
// import { PipeArrayBuffer } from "@dfinity/candid/lib/cjs/utils/buffer";

function equal(buf1, buf2) {
  return compare(buf1, buf2) === 0;
}

export default async function validateBody(
  canisterId,
  path,
  body,
  certificate,
  tree,
  agent
) {
  //await agent.fetchRootKey();
  //console.log("Root key= ");
  //console.log(agent.rootKey);

  let cert;
  try {
    cert = await Certificate.create({
      certificate,
      canisterId,
      rootKey: agent.rootKey
    });
  } catch (error) {
    return false;
  }

  const hashTree = Cbor.decode(tree);
  const reconstructed = await reconstruct(hashTree);
  const witness = cert.lookup([
    "canister",
    canisterId.toUint8Array(),
    "certified_data"
  ]);

  if (!witness) {
    throw new Error(
      "Could not find certified data for this canister in the certificate."
    );
  }

  // First validate that the Tree is as good as the certification.
  if (!equal(witness, reconstructed)) {
    console.error("Witness != Tree passed in ic-certification");
    return false;
  }

  // Next, calculate the SHA of the content.
  const sha = await crypto.subtle.digest("SHA-256", body);
  let treeSha = lookup_path(["websocket", path], hashTree);

  if (!treeSha) {
    // Allow fallback to `index.html`.
    treeSha = lookup_path(["websocket"], hashTree);
  }

  if (!treeSha) {
    // The tree returned in the certification header is wrong. Return false.
    // We don't throw here, just invalidate the request.
    console.error(
      `Invalid Tree in the header. Does not contain path ${JSON.stringify(
        path
      )}`
    );
    return false;
  }

  return !!treeSha && equal(sha, treeSha);
}
