var G2 = artifacts.require("libraries/BN256G2.sol");
var BnCurve = artifacts.require("libraries/G.sol");
var SetupPublicParams = artifacts.require("contracts/SetupPublicParams.sol");
var RequestCredential = artifacts.require("contracts/RequestCredential.sol");
var IssueCredential = artifacts.require("contracts/IssueCredential.sol");
var VerifyCredential = artifacts.require("contracts/VerifyCredential.sol");

// deployed by issuer 0
const Issuer0Address = "0xd269f26ce290cD91dE697Fb96f5e5E40120d2514";
// deployed by service provider 
// second last address
const ServiceProviderAddress = "0xa410a49DbF0aC680E1F102BC0E736043Da9625c7";

module.exports = async function (deployer) {
  try {
    // Deploy and link libraries
    await deployer.deploy(G2, { from: Issuer0Address  });
    const G2Instance = await G2.deployed();
    await deployer.link(G2, BnCurve);
    
    await deployer.deploy(BnCurve, { from: Issuer0Address  });
    const BnCurveInstance = await BnCurve.deployed();
    // Link BnCurve to SetupPublicParams, RequestCredential, and IssueCredential before deploying them
    await deployer.link(BnCurve, [SetupPublicParams, RequestCredential, IssueCredential]);

    // Deploy contracts
    await deployer.deploy(SetupPublicParams, { from: Issuer0Address });
    const SetupPublicParamsInstance = await SetupPublicParams.deployed();

    await deployer.deploy(RequestCredential, { from: Issuer0Address });
    const RequestCredentialInstance = await RequestCredential.deployed();


    await deployer.deploy(IssueCredential, { from: Issuer0Address });
    const IssueCredentialInstance = await IssueCredential.deployed();
    
    await deployer.deploy(VerifyCredential, { from: ServiceProviderAddress });
    const VerifyCredentialInstance = await VerifyCredential.deployed();
    // Log deployed contract addresses
    console.log("SetupPublicParamsInstance address:", SetupPublicParamsInstance.address);
    console.log("RequestCredentialInstance address:", RequestCredentialInstance.address);
    console.log("IssueCredentialInstance address:", IssueCredentialInstance.address);
    console.log("VerifyCredentialInstance address:", VerifyCredentialInstance.address);

    

  } catch (error) {
    console.error("Error deploying contracts:", error);
  }
};
