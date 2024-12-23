
var G2 = artifacts.require("./libraries/BN256G2");
var BnCurve = artifacts.require("./libraries/G");
var Request = artifacts.require("./contracts/RequestCredential");
var Params = artifacts.require("./contracts/SetupPublicParams");
var Verify = artifacts.require("./contracts/VerifyCredential");
var Issue = artifacts.require("./contracts/IssueCredential");

module.exports = async function (deployer) {

  await deployer.deploy(G2, {from: "0x44f36B90CA76A5E37b79909BFA1077d87705a6B7"});
  const g2 = await G2.deployed()

  await deployer.link(G2, BnCurve);
  await deployer.deploy(BnCurve, {from: "0x44f36B90CA76A5E37b79909BFA1077d87705a6B7"});
  const bnCurve = await BnCurve.deployed()

  await deployer.link(BnCurve, Params);
  await deployer.deploy(Params, {from: "0x44f36B90CA76A5E37b79909BFA1077d87705a6B7"});
  const params = await Params.deployed()

  
  await deployer.link(BnCurve, Verify);
  await deployer.link(G2, Verify);
  await deployer.deploy(Verify, params.address, {from: "0xF1305F279c2616972b97b86759bE44a528E88d6d"});
  const verify = await Verify.deployed()
  
  await deployer.link(BnCurve, Request);
  await deployer.link(G2, Request);
  await deployer.deploy(Request, params.address, {from: "0x44f36B90CA76A5E37b79909BFA1077d87705a6B7"});
  const request = await Request.deployed()

  await deployer.deploy(Issue, params.address, {from: "0x44f36B90CA76A5E37b79909BFA1077d87705a6B7"});
  const issue = await Issue.deployed()

  console.log(issue.address);
  console.log(request.address);
  console.log(params.address);
  console.log(verify.address);

};