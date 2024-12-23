var G2 = artifacts.require("libraries/BN256G2.sol");
var BnCurve = artifacts.require("libraries/G.sol");
var SetupPublicParams = artifacts.require("contracts/SetupPublicParams.sol");
var RequestCredential = artifacts.require("contracts/RequestCredential.sol");
var IssueCredential = artifacts.require("contracts/IssueCredential.sol");
var VerifyCredential = artifacts.require("contracts/VerifyCredential.sol");

// deployed by issuer 0
const Issuer0Address = "0x92A17e2575A714FAeb1a94880FF097d85c2fA713";
// const deploymentAddress = "0xa0AbA55a5e4063151c01Ac15387e7DB2C94Bbe52";
// deployed by srvice provider
const ServiceProviderAddress = "0x0cfD57d46E32371551731eE4bEddB0E8cAdFCc42";

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
