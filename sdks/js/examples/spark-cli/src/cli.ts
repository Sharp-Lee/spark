import { IssuerSparkWallet } from "@buildonspark/issuer-sdk";
import { getLatestDepositTxId } from "@buildonspark/spark-sdk";
import { TokenTransactionStatus } from "@buildonspark/spark-sdk/proto/spark";
import {
  ConfigOptions,
  LOCAL_WALLET_CONFIG,
  MAINNET_WALLET_CONFIG,
  REGTEST_WALLET_CONFIG,
} from "@buildonspark/spark-sdk/services/wallet-config";
import { ExitSpeed } from "@buildonspark/spark-sdk/types";
import {
  getNetwork,
  getP2TRScriptFromPublicKey,
  Network,
} from "@buildonspark/spark-sdk/utils";
import { hexToBytes } from "@noble/curves/abstract/utils";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1";
import { hex } from "@scure/base";
import { Address, OutScript, Transaction } from "@scure/btc-signer";
import readline from "readline";
import fs from "fs";
import fsSync, { existsSync, mkdirSync } from "node:fs";
import fsPromises from "node:fs/promises";
import crypto from "node:crypto";
import path from "node:path";
import { SparkAddressFormat } from "@buildonspark/spark-sdk/address";

import {
  MIN_PASSWORD_LENGTH,
  ENCRYPTED_WALLET_FILE_PATH,
  WALLET_DATA_DIR,
  PBKDF2_ITERATIONS,
  KEY_LENGTH,
  SALT_LENGTH,
  IV_LENGTH
} from './constants.js';
import { promptForPassword, promptForConfirmation } from './utils.js';
import * as bip39 from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";

// Define structure for the encrypted file
interface EncryptedFileContent {
    salt: string; // Salt for PBKDF2 key derivation
    iv: string;   // Initialization Vector for AES
    authTag: string; // GCM auth tag
    encryptedMnemonic: string; // Encrypted mnemonic
}

const commands = [
  "initwallet",
  "lockwallet",
  "unlockwallet",
  "exportmnemonic",
  "changepassword",
  "deletewallet",
  "createwallet",
  "switchwallet",
  "getbalance",
  "getdepositaddress",
  "identity",
  "getsparkaddress",
  "getlatesttx",
  "claimdeposit",
  "gettransfers",
  "createinvoice",
  "payinvoice",
  "sendtransfer",
  "withdraw",
  "withdrawalfee",
  "lightningsendfee",
  "getlightningsendrequest",
  "getlightningreceiverequest",
  "getcoopexitrequest",
  "transfertokens",
  "gettokenl1address",
  "getissuertokenbalance",
  "getissuertokeninfo",
  "getissuertokenpublickey",
  "minttokens",
  "burntokens",
  "freezetokens",
  "unfreezetokens",
  "getissuertokenactivity",
  "announcetoken",
  "nontrustydeposit",
  "querytokentransactions",
  "help",
  "exit",
  "quit",
];

let activeSparkWallet: IssuerSparkWallet | undefined;
let globalCliSdkBaseConfig: ConfigOptions = {};
let globalCliNetworkType: string = "REGTEST";
let currentSessionMnemonic: string | null = null;
let currentWalletName: string | null = null;

function getWalletFilePath(walletName: string): string {
  return path.join(WALLET_DATA_DIR, `${walletName}.json`);
}

async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha512', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

async function encryptMnemonic(mnemonic: string, password: string): Promise<string | null> {
  try {
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = await deriveKey(password, salt);
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    let encrypted = cipher.update(mnemonic, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    const payload: EncryptedFileContent = {
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      encryptedMnemonic: encrypted,
    };
    return JSON.stringify(payload);
  } catch (error) {
    console.error("加密助记词时出错:", error);
    return null;
  }
}

async function decryptMnemonic(encryptedPayloadStr: string, password: string): Promise<string | null> {
  try {
    const payload: EncryptedFileContent = JSON.parse(encryptedPayloadStr);
    const salt = Buffer.from(payload.salt, 'hex');
    const key = await deriveKey(password, salt);
    const iv = Buffer.from(payload.iv, 'hex');
    const authTag = Buffer.from(payload.authTag, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(payload.encryptedMnemonic, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    return null;
  }
}

async function saveEncryptedWallet(encryptedMnemonicJson: string, walletName: string): Promise<boolean> {
  try {
    if (!existsSync(WALLET_DATA_DIR)) {
      mkdirSync(WALLET_DATA_DIR, { recursive: true });
    }
    const filePath = getWalletFilePath(walletName);
    const tempFilePath = filePath + '.tmp';
    await fsPromises.writeFile(tempFilePath, encryptedMnemonicJson, 'utf8');
    await fsPromises.rename(tempFilePath, filePath);
    console.log(`钱包已加密并保存至: ${filePath}`);
    return true;
  } catch (error) {
    console.error("保存加密钱包失败:", error);
    return false;
  }
}

async function loadAndInitializeWallet(password: string, walletName: string): Promise<boolean> {
  const filePath = getWalletFilePath(walletName);
  if (!existsSync(filePath)) {
    console.error(`钱包文件不存在: ${filePath}`);
    return false;
  }
  try {
    const encryptedPayloadStr = await fsPromises.readFile(filePath, 'utf8');
    const decryptedMnemonic = await decryptMnemonic(encryptedPayloadStr, password);
    if (decryptedMnemonic) {
      currentSessionMnemonic = decryptedMnemonic;
      const options: ConfigOptions = { 
        ...globalCliSdkBaseConfig, 
        network: globalCliNetworkType as any,
      };
      const { wallet } = await IssuerSparkWallet.initialize({ mnemonicOrSeed: currentSessionMnemonic, options });
      activeSparkWallet = wallet;
      currentWalletName = walletName; // Set current wallet name
      return true;
    }
    return false;
  } catch (error) {
    console.error(`加载并初始化钱包 (${walletName}) 失败:`, error);
    return false;
  }
}

function isWalletLocked(): boolean {
  return !currentSessionMnemonic || !activeSparkWallet;
}

function lockWallet() {
  activeSparkWallet?.cleanupConnections();
  activeSparkWallet = undefined;
  currentSessionMnemonic = null;
  currentWalletName = null; // Clear current wallet name
  console.log("钱包已锁定。");
}

async function runCLI() {
  globalCliNetworkType = (() => {
    const envNetwork = process.env.NETWORK?.toUpperCase();
    if (envNetwork === "MAINNET" || envNetwork === "LOCAL" || envNetwork === "REGTEST") return envNetwork;
    console.warn(`无效的 NETWORK 环境变量: ${process.env.NETWORK}. 默认使用 REGTEST.`);
    return "REGTEST";
  })();

  const configFile = process.env.CONFIG_FILE;
  if (configFile) {
    try {
      if (fsSync.existsSync(configFile)) {
        const data = fsSync.readFileSync(configFile, "utf8");
        const parsedConfig = JSON.parse(data) as ConfigOptions;
        if (parsedConfig.network && parsedConfig.network.toUpperCase() !== globalCliNetworkType) {
          console.warn(`网络不匹配: 环境变量 NETWORK 为 ${globalCliNetworkType} 但配置文件指定 ${parsedConfig.network}. 将优先使用环境变量指定的网络.`);
          globalCliSdkBaseConfig = { ...parsedConfig, network: globalCliNetworkType as any };
        } else {
          globalCliSdkBaseConfig = parsedConfig;
        }
      } else {
        console.warn(`配置文件 "${configFile}" 未找到. 使用默认 SDK 配置.`);
        setDefaultSdkConfig();
      }
    } catch (err) {
      console.error("读取或解析配置文件错误:", err, "\n使用默认 SDK 配置.");
      setDefaultSdkConfig();
    }
  } else {
    setDefaultSdkConfig();
  }
  globalCliSdkBaseConfig = { ...globalCliSdkBaseConfig, network: globalCliNetworkType as any };

  function setDefaultSdkConfig() {
    switch (globalCliNetworkType) {
      case "MAINNET": globalCliSdkBaseConfig = MAINNET_WALLET_CONFIG; break;
      case "LOCAL": globalCliSdkBaseConfig = LOCAL_WALLET_CONFIG; break;
      default: globalCliSdkBaseConfig = REGTEST_WALLET_CONFIG; break;
    }
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    completer: (line: string) => {
      const commandLower = line.toLowerCase();
      const completions = commands.filter((c) => c.startsWith(commandLower));
      return [completions.length ? completions : commands, line];
    },
  });

  // Revised initial wallet loading logic
  const walletFiles = موجودWalletFiles();
  if (walletFiles.length > 0) {
    console.log("检测到已保存的钱包。");
    if (walletFiles.length === 1) {
      const singleWalletName = walletFiles[0].replace('.json', '');
      console.log(`找到钱包: ${singleWalletName}`);
      let attempts = 0;
      while(attempts < 3 && isWalletLocked()) {
        const password = await promptForPassword(`请输入主密码以解锁钱包 '${singleWalletName}': `, rl);
        if (!password) { console.log("已取消解锁。"); break;}
        const success = await loadAndInitializeWallet(password, singleWalletName);
        if (success) {
          console.log(`钱包 '${singleWalletName}' 已成功解锁并加载。`);
          break;
        }
        attempts++;
        console.log(`密码错误或解密失败。 ${attempts < 3 ? `剩余尝试次数: ${3-attempts}`: ""}`);
      }
      if (isWalletLocked() && attempts >= 3) {
        console.log("解锁失败次数过多。钱包保持锁定状态。");
      }
    } else {
      console.log("找到多个钱包文件。请使用 'unlockwallet <walletName>' 或 'switchwallet <walletName>' 来加载特定钱包。");
      console.log("可用钱包:", walletFiles.map(f => f.replace('.json', '')).join(", "));
    }
  } else {
    console.log("未找到本地钱包配置。请使用 'initwallet' 创建新钱包或导入现有钱包。");
  }
  
  const helpMessage = `
  钱包管理命令:
  initwallet [助记词]             - 初始化/导入钱包并可选加密保存。
  lockwallet                      - 锁定当前会话的钱包。
  unlockwallet                    - (如果已锁定) 提示输入密码以解锁钱包。
  exportmnemonic                  - (需解锁) 显示当前钱包的主助记词。
  changepassword                  - (需解锁) 更改加密钱包的主密码。
  deletewallet                    - 删除本地加密的钱包文件 (需确认)。
  createwallet <walletName>        - 创建新钱包并可选加密保存。
  switchwallet <walletName>        - 切换到指定钱包。

  常规钱包操作 (需解锁):
  getbalance                      - 获取钱包余额。
  getdepositaddress               - 获取从 L1 到 Spark 的存款地址
  identity                        - 获取钱包的身份公钥
  getsparkaddress                 - 获取钱包的 spark 地址
  getlatesttx <address>           - 获取地址的最新存款交易 id
  claimdeposit <txid>             - 认领任何待处理的存款到钱包
  gettransfers [limit] [offset]   - 获取转账列表
  createinvoice <amount> <memo>     - 创建新的闪电发票
  payinvoice <invoice> <maxFeeSats> - 支付闪电发票
  sendtransfer <amount> <receiverSparkAddress> - 发送 spark 转账
  withdraw <amount> <onchainAddress> <exitSpeed(FAST|MEDIUM|SLOW)> - 将资金提取到 L1 地址
  withdrawalfee <amount> <withdrawalAddress> - 获取提现（合作退出）的费用估计
  lightningsendfee <invoice>       - 获取闪电发送费用估计
  getlightningsendrequest <requestId> - 通过 ID 获取闪电发送请求
  getlightningreceiverequest <requestId> - 通过 ID 获取闪电接收请求
  getcoopexitrequest <requestId>   - 通过 ID 获取合作退出请求

  Token Holder Commands:
  transfertokens <tokenPubKey> <amount> <receiverPubKey> - 转账

  Token Issuer Commands:
  gettokenl1address               - 获取链上令牌操作的 L1 地址
  getissuertokenbalance           - 获取发行者的令牌余额
  getissuertokeninfo              - 获取发行者的令牌信息
  getissuertokenpublickey         - 获取发行者的令牌公钥
  minttokens <amount>             - 铸造新令牌
  burntokens <amount>             - 烧毁令牌
  freezetokens <sparkAddress>     - 冻结令牌以供特定地址使用
  unfreezetokens <sparkAddress>   - 解冻令牌以供特定地址使用
  getissuertokenactivity          - 获取发行者的令牌活动
  announcetoken <tokenName> <tokenTicker> <decimals> <maxSupply> <isFreezable> - 在 L1 上宣布令牌

  help                            - 显示此帮助信息。
  exit/quit                       - 退出程序。
  `;
  console.log(helpMessage);

  while (true) {
    const promptPrefix = isWalletLocked() ? "(已锁定) > " : `(${globalCliNetworkType}${currentWalletName ? '/' + currentWalletName : ''}) > `;
    const commandInput = await new Promise<string>((resolve) => {
      rl.question(promptPrefix, resolve);
    });

    const [firstWord, ...args] = commandInput.trim().split(/\s+/);
    const lowerCommand = firstWord?.toLowerCase();

    if (!lowerCommand) continue;

    if (lowerCommand === "exit" || lowerCommand === "quit") {
      lockWallet();
      rl.close();
      console.log("已退出。");
      break;
    }

    try {
      switch (lowerCommand) {
        case "help":
          console.log(helpMessage);
          break;

        case "initwallet":
          let targetWalletName = "";
          if (args.length > 0 && !bip39.validateMnemonic(args.join(" "), wordlist)) {
            // Assume first arg is wallet name if it's not a mnemonic
            targetWalletName = args.shift() as string;
            console.log(`将使用钱包名称: ${targetWalletName}`);
          }

          if (!targetWalletName) {
            targetWalletName = await new Promise<string>(resolve => rl.question("请输入新钱包的名称 (例如: primary): ", resolve));
            if (!targetWalletName) {
              console.log("钱包名称不能为空，操作已取消。");
              break;
            }
          }
          
          const walletPathForInit = getWalletFilePath(targetWalletName);
          if (existsSync(walletPathForInit)) {
            const confirmOverwrite = await promptForConfirmation(
              `警告: 钱包文件 '${targetWalletName}.json' 已存在。重新初始化将覆盖它。是否继续?`, rl
            );
            if (!confirmOverwrite) { console.log("操作已取消。"); break; }
          }
          lockWallet(); // Lock any existing wallet before initializing a new one

          let mnemonicToUse: string;
          if (args.length > 0) { // Remaining args could be a mnemonic
            const potentialMnemonic = args.join(" ");
            if (!bip39.validateMnemonic(potentialMnemonic, wordlist)) {
              console.error("提供的助记词无效。"); break;
            }
            mnemonicToUse = potentialMnemonic;
            console.log("正在导入提供的助记词...");
          } else {
            const importChoice = await promptForConfirmation("是否要导入现有助记词? (否则将生成新的)", rl);
            if (importChoice) {
              mnemonicToUse = await new Promise<string>(resolve => rl.question("请输入助记词: ", resolve));
              if (!bip39.validateMnemonic(mnemonicToUse, wordlist)) {
                console.error("提供的助记词无效。"); break;
              }
              console.log("\n!!! 新生成的助记词 (请务必安全备份) !!!\n" + mnemonicToUse + "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            } else {
              mnemonicToUse = bip39.generateMnemonic(wordlist, 128);
              console.log("\n!!! 新生成的助记词 (请务必安全备份) !!!\n" + mnemonicToUse + "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
            }
          }
          
          currentSessionMnemonic = mnemonicToUse;
          const sdkOptions: ConfigOptions = { ...globalCliSdkBaseConfig, network: globalCliNetworkType as any };
          try {
            const { wallet } = await IssuerSparkWallet.initialize({ mnemonicOrSeed: currentSessionMnemonic, options: sdkOptions });
            activeSparkWallet = wallet;
            currentWalletName = targetWalletName; // Set current wallet name
            console.log(`钱包 '${targetWalletName}' 已在当前会话中初始化。`);
          } catch (initError) {
            console.error("使用助记词初始化钱包实例失败:", initError);
            currentSessionMnemonic = null;
            currentWalletName = null;
            break;
          }

          const saveChoice = await promptForConfirmation(`是否要用密码加密并保存此钱包 ('${targetWalletName}.json') 以供将来使用?`, rl);
          if (saveChoice) {
            let newPassword = "";
            let confirmPwd = "";
            let attempts = 0;
            while(attempts < 3) {
              newPassword = await promptForPassword("设置主密码 (最少8位): ", rl);
              if (newPassword.length < MIN_PASSWORD_LENGTH) {
                console.log(`密码太短，至少需要 ${MIN_PASSWORD_LENGTH} 位。`);
                attempts++; continue;
              }
              confirmPwd = await promptForPassword("确认主密码: ", rl);
              if (newPassword === confirmPwd) break;
              console.log("密码不匹配，请重试。");
              attempts++;
            }
            if (newPassword !== confirmPwd) { console.log("密码确认失败，钱包未保存。"); break; }

            const encryptedPayload = await encryptMnemonic(currentSessionMnemonic, newPassword);
            if (encryptedPayload) {
              await saveEncryptedWallet(encryptedPayload, targetWalletName);
            } else {
              console.log("加密失败，钱包未保存。");
            }
          } else {
            console.log(`钱包 '${targetWalletName}' 仅在当前会话中可用，关闭CLI后将丢失（除非已另外保存助记词或已加密保存）。`);
          }
          break;
        
        case "lockwallet":
          lockWallet();
          break;

        case "unlockwallet":
          if (!isWalletLocked()) { console.log(`钱包 '${currentWalletName}' 已经解锁。`); break; }
          
          let walletToUnlock = args[0];
          const availableWallets = موجودWalletFiles().map(f => f.replace('.json', ''));

          if (!walletToUnlock) {
            if (availableWallets.length === 0) {
              console.log("未找到本地加密钱包文件。请先使用 'initwallet'。"); break;
            } else if (availableWallets.length === 1) {
              walletToUnlock = availableWallets[0];
              console.log(`尝试解锁唯一的钱包: ${walletToUnlock}`);
            } else {
              console.log("找到多个钱包。请指定要解锁的钱包名称: unlockwallet <walletName>");
              console.log("可用钱包:", availableWallets.join(", "));
              break;
            }
          }

          if (!getWalletFilePath(walletToUnlock) || !existsSync(getWalletFilePath(walletToUnlock))) {
             console.log(`未找到名为 '${walletToUnlock}' 的本地加密钱包文件。`);
             if (availableWallets.length > 0) console.log("可用钱包:", availableWallets.join(", "));
             break;
          }

          let unlockAttempts = 0;
          while(unlockAttempts < 3 && isWalletLocked()) {
            const password = await promptForPassword(`请输入主密码以解锁钱包 '${walletToUnlock}': `, rl);
            if (!password) { console.log("已取消解锁。"); break; }
            const success = await loadAndInitializeWallet(password, walletToUnlock);
            if (success) { console.log(`钱包 '${walletToUnlock}' 已成功解锁。`); break; }
            unlockAttempts++;
            console.log(`密码错误或解密失败。 ${unlockAttempts < 3 ? `剩余尝试次数: ${3-unlockAttempts}`: "解锁失败次数过多。"}`);
          }
          break;

        case "exportmnemonic":
          if (isWalletLocked()) { console.log("请先解锁钱包。"); break; }
          console.log("\n!!! 安全警告 - 主助记词 !!!");
          console.log(currentSessionMnemonic);
          console.log("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n建议抄写后立即清除终端显示。");
          break;
        
        case "changepassword":
          let walletToChangePass = args[0];
          if (!walletToChangePass && currentWalletName && !isWalletLocked()) {
            walletToChangePass = currentWalletName;
            console.log(`将为当前已解锁的钱包 '${walletToChangePass}' 更改密码。`);
          } else if (!walletToChangePass) {
            const available = موجودWalletFiles().map(f => f.replace('.json', ''));
            if (available.length === 0) { console.log("未找到加密钱包。"); break; }
            console.log("请指定要更改密码的钱包名称: changepassword <walletName>");
            if (currentWalletName) console.log(`(当前活动钱包: ${currentWalletName})`);
            console.log("可用钱包:", available.join(", "));
            break;
          }
          
          const walletPathForChange = getWalletFilePath(walletToChangePass);
          if (!existsSync(walletPathForChange)) {console.log(`未找到名为 '${walletToChangePass}' 的加密钱包文件。无法更改密码。`); break;}
          
          console.log(`更改钱包 '${walletToChangePass}' 的主密码需要您输入当前密码。`);
          const oldPassword = await promptForPassword(`请输入钱包 '${walletToChangePass}' 的当前主密码: `, rl);
          const encryptedData = await fsPromises.readFile(walletPathForChange, 'utf8');
          const tempMnemonic = await decryptMnemonic(encryptedData, oldPassword);
          
          if (!tempMnemonic) { console.log("当前密码不正确。操作取消。"); break; }

          let newPass = ""; let confirmNewPass = ""; let changeAttempts = 0;
          while(changeAttempts < 3) {
            newPass = await promptForPassword("请输入新主密码 (最少8位): ", rl);
            if (newPass.length < MIN_PASSWORD_LENGTH) { console.log("新密码太短。"); changeAttempts++; continue; }
            confirmNewPass = await promptForPassword("确认新主密码: ", rl);
            if (newPass === confirmNewPass) break;
            console.log("新密码不匹配。"); changeAttempts++;
          }
          if (newPass !== confirmNewPass) { console.log("新密码确认失败。密码未更改。"); break; }
          
          const newEncryptedPayload = await encryptMnemonic(tempMnemonic, newPass);
          if (newEncryptedPayload && await saveEncryptedWallet(newEncryptedPayload, walletToChangePass)) {
            console.log(`钱包 '${walletToChangePass}' 的主密码已成功更改。`);
            // If changing password for the currently active wallet, re-establish session with new reality
            if (currentWalletName === walletToChangePass && activeSparkWallet) {
              currentSessionMnemonic = tempMnemonic; // Mnemonic is the same
              console.log("当前活动钱包的密码已更新。");
            } else if (currentWalletName === walletToChangePass && !activeSparkWallet) {
              // Wallet was not active, but its name matched. We can try to load it.
              // This case is less likely if it required unlocking to get here.
            }
          } else {
            console.log("更改密码失败，钱包文件未更新。");
          }
          break;

        case "deletewallet":
          const walletNameToDelete = args[0];
          if (!walletNameToDelete) {
            console.log("请提供要删除的钱包名称: deletewallet <walletName>");
            const available = موجودWalletFiles().map(f => f.replace('.json', ''));
            if (available.length > 0) console.log("可用钱包:", available.join(", "));
            break;
          }
          const walletPathToDelete = getWalletFilePath(walletNameToDelete);
          if (!existsSync(walletPathToDelete)) { console.log(`名为 '${walletNameToDelete}' 的本地加密钱包不存在。`); break; }
          
          const confirmDelete = await promptForConfirmation(
            `警告: 这将永久删除本地加密的钱包文件 ('${walletNameToDelete}.json')。您的助记词不会从您已备份的地方删除，但此CLI将无法再自动加载它。是否继续?`, rl
          );
          if (confirmDelete) {
            try {
              await fsPromises.unlink(walletPathToDelete);
              console.log(`本地加密钱包文件 '${walletNameToDelete}.json' 已删除。`);
              if (currentWalletName === walletNameToDelete) {
                lockWallet(); // Lock if the active wallet was deleted
              }
            } catch (delError) {
              console.error("删除钱包文件失败:", delError);
            }
          } else {
            console.log("操作已取消。");
          }
          break;

        case "createwallet":
          let newWalletName = args[0];
          if (!newWalletName) {
            newWalletName = await new Promise<string>(resolve => rl.question("请输入新钱包的名称: ", resolve));
            if (!newWalletName) {
              console.log("钱包名称不能为空，操作已取消。");
              break;
            }
          }

          const newWalletPath = getWalletFilePath(newWalletName);
          if (existsSync(newWalletPath)) {
            const confirmOverwrite = await promptForConfirmation(
              `警告: 钱包文件 '${newWalletName}.json' 已存在。是否覆盖?`, rl
            );
            if (!confirmOverwrite) {
              console.log("操作已取消。保留现有钱包。");
              break;
            }
          }

          lockWallet(); // Lock any current wallet session

          const newMnemonic = bip39.generateMnemonic(wordlist, 128);
          console.log("\n!!! 新生成的助记词 (请务必安全备份) !!!\n" + newMnemonic + "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");

          currentSessionMnemonic = newMnemonic;
          const sdkOpts: ConfigOptions = { ...globalCliSdkBaseConfig, network: globalCliNetworkType as any };
          try {
            const { wallet } = await IssuerSparkWallet.initialize({ mnemonicOrSeed: currentSessionMnemonic, options: sdkOpts });
            activeSparkWallet = wallet;
            currentWalletName = newWalletName;
            console.log(`新钱包 '${newWalletName}' 已创建并在当前会话中激活。`);
          } catch (initError) {
            console.error(`使用新助记词初始化钱包 '${newWalletName}' 失败:`, initError);
            currentSessionMnemonic = null;
            currentWalletName = null;
            activeSparkWallet = undefined;
            break;
          }

          const encryptChoice = await promptForConfirmation(`是否要用密码加密并保存钱包 '${newWalletName}.json'?`, rl);
          if (encryptChoice) {
            let password = "";
            let confirmPass = "";
            let pwdAttempts = 0;
            while (pwdAttempts < 3) {
              password = await promptForPassword("设置主密码 (最少8位): ", rl);
              if (password.length < MIN_PASSWORD_LENGTH) {
                console.log(`密码太短，至少需要 ${MIN_PASSWORD_LENGTH} 位。`);
                pwdAttempts++; continue;
              }
              confirmPass = await promptForPassword("确认主密码: ", rl);
              if (password === confirmPass) break;
              console.log("密码不匹配，请重试。");
              pwdAttempts++;
            }
            if (password !== confirmPass) {
              console.log("密码确认失败。钱包已在当前会话激活但未加密保存。");
              break;
            }
            const encryptedPayload = await encryptMnemonic(currentSessionMnemonic, password);
            if (encryptedPayload) {
              await saveEncryptedWallet(encryptedPayload, newWalletName);
            } else {
              console.log(`加密钱包 '${newWalletName}' 失败。钱包已在当前会话激活但未保存。`);
            }
          } else {
            console.log(`钱包 '${newWalletName}' 已在当前会话激活但未加密保存。关闭CLI后将丢失（除非已另外备份助记词）。`);
          }
          break;

        case "switchwallet":
          let switchToWalletName = args[0];
          const availableWalletsForSwitch = موجودWalletFiles().map(f => f.replace('.json', ''));

          if (!switchToWalletName) {
            if (availableWalletsForSwitch.length === 0) {
              console.log("未找到可切换的本地钱包。请先使用 'initwallet' 或 'createwallet'。");
              break;
            }
            console.log("可用钱包列表:");
            availableWalletsForSwitch.forEach((name, index) => console.log(`${index + 1}. ${name}`));
            const choice = await new Promise<string>(resolve => rl.question("请选择要切换到的钱包编号或名称: ", resolve));
            const choiceNum = parseInt(choice);
            if (!isNaN(choiceNum) && choiceNum > 0 && choiceNum <= availableWalletsForSwitch.length) {
              switchToWalletName = availableWalletsForSwitch[choiceNum - 1];
            } else if (availableWalletsForSwitch.includes(choice)) {
              switchToWalletName = choice;
            } else {
              console.log("无效的选择。");
              break;
            }
          }

          if (!existsSync(getWalletFilePath(switchToWalletName))) {
            console.log(`错误: 钱包文件 '${switchToWalletName}.json' 未找到。`);
            if (availableWalletsForSwitch.length > 0) {
              console.log("可用钱包:", availableWalletsForSwitch.join(", "));
            }
            break;
          }

          if (currentWalletName === switchToWalletName && !isWalletLocked()) {
            console.log(`钱包 '${switchToWalletName}' 已经是当前活动钱包。`);
            break;
          }

          if (!isWalletLocked()) {
            console.log(`正在锁定当前钱包: ${currentWalletName}...`);
            lockWallet();
          }
          
          let switchAttempts = 0;
          while (switchAttempts < 3) {
            const password = await promptForPassword(`请输入钱包 '${switchToWalletName}' 的主密码: `, rl);
            if (!password) { console.log("已取消切换操作。"); break; }
            const success = await loadAndInitializeWallet(password, switchToWalletName);
            if (success) {
              console.log(`已成功切换到钱包: '${switchToWalletName}'。`);
              break;
            }
            switchAttempts++;
            console.log(`密码错误或解密失败。${switchAttempts < 3 ? `剩余尝试次数: ${3 - switchAttempts}` : "切换失败次数过多。"}`);
            if (switchAttempts >=3) break;
          }
          break;

        default:
          if (isWalletLocked()) {
            if (commands.includes(lowerCommand)) {
              console.log("钱包已锁定或未初始化。请使用 'initwallet' 初始化或 'unlockwallet' 解锁。");
            } else {
              console.log("未知命令。输入 'help' 查看可用命令。");
            }
            break;
          }
          
          const currentWalletInstance = activeSparkWallet!; 

          switch (lowerCommand) {
            case "getbalance":
              const balanceInfo = await currentWalletInstance.getBalance();
              console.log("Sats Balance: " + balanceInfo.balance);
              if (balanceInfo.tokenBalances && balanceInfo.tokenBalances.size > 0) {
                console.log("\nToken Balances:");
                for (const [tokenPublicKey,tokenInfo,] of balanceInfo.tokenBalances.entries()) {
                  console.log(`  Token (${tokenPublicKey}):`);
                  console.log(`    Balance: ${tokenInfo.balance}`);
                }
              }
              break;
            case "getdepositaddress":
              const depositAddress = await currentWalletInstance.getSingleUseDepositAddress();
              console.log("警告: 此为一次性存款地址，请勿重复使用，否则可能导致资金损失!");
              console.log(depositAddress);
              break;
            case "identity":
              const identityBytes = await currentWalletInstance.getIdentityPublicKey();
              console.log("身份公钥 (hex):", identityBytes);
              break;
            case "getsparkaddress":
              const sparkAddress: SparkAddressFormat = await currentWalletInstance.getSparkAddress();
              console.log("Spark 地址:", sparkAddress);
              break;
            case "claimdeposit":
              const depositResult = await currentWalletInstance.claimDeposit(args[0]);
              await new Promise((resolve) => setTimeout(resolve, 1000));
              console.log(depositResult);
              break;
            case "gettransfers":
              const limit = args[0] ? parseInt(args[0]) : 10;
              const offset = args[1] ? parseInt(args[1]) : 0;
              if (isNaN(limit) || isNaN(offset)) {
                console.log("Invalid limit or offset");
                break;
              }
              if (limit < 0 || offset < 0) {
                console.log("Limit and offset must be non-negative");
                break;
              }
              const transfers = await currentWalletInstance.getTransfers(limit, offset);
              console.log(transfers);
              break;
            case "createinvoice":
              const invoice = await currentWalletInstance.createLightningInvoice({
                amountSats: parseInt(args[0]),
                memo: args[1],
              });
              console.log(invoice);
              break;
            case "payinvoice":
              let maxFeeSats = parseInt(args[1]);
              if (isNaN(maxFeeSats)) {
                console.log("Invalid maxFeeSats value");
                break;
              }
              const payment = await currentWalletInstance.payLightningInvoice({
                invoice: args[0],
                maxFeeSats: maxFeeSats,
              });
              console.log(payment);
              break;
            case "sendtransfer":
              const transfer = await currentWalletInstance.transfer({
                amountSats: parseInt(args[0]),
                receiverSparkAddress: args[1],
              });
              console.log(transfer);
              break;
            case "withdraw":
              const withdrawal = await currentWalletInstance.withdraw({
                amountSats: parseInt(args[0]),
                onchainAddress: args[1],
                exitSpeed: args[2] as ExitSpeed,
              });
              console.log(withdrawal);
              break;
            case "withdrawalfee": {
              const fee = await currentWalletInstance.getWithdrawalFeeEstimate({
                amountSats: parseInt(args[0]),
                withdrawalAddress: args[1],
              });
              console.log(fee);
              break;
            }
            case "lightningsendfee": {
              const fee = await currentWalletInstance.getLightningSendFeeEstimate({
                encodedInvoice: args[0],
              });
              console.log(fee);
              break;
            }
            case "gettokenl1address": {
              const l1Address = await currentWalletInstance.getTokenL1Address();
              console.log(l1Address);
              break;
            }
            case "getissuertokenbalance": {
              const balance = await currentWalletInstance.getIssuerTokenBalance();
              console.log("Issuer Token Balance:", balance.balance.toString());
              break;
            }
            case "getissuertokeninfo": {
              const info = await currentWalletInstance.getIssuerTokenInfo();
              if (info) {
                console.log("Token Info:", {
                  tokenPublicKey: info.tokenPublicKey,
                  tokenName: info.tokenName,
                  tokenSymbol: info.tokenSymbol,
                  tokenDecimals: info.tokenDecimals,
                  maxSupply: info.maxSupply.toString(),
                  isFreezable: info.isFreezable,
                });
              } else {
                console.log("No token info found");
              }
              break;
            }
            case "getissuertokenpublickey": {
              const pubKey = await currentWalletInstance.getIdentityPublicKey();
              console.log("Issuer Token Public Key:", pubKey);
              break;
            }
            case "minttokens": {
              const amount = BigInt(parseInt(args[0]));
              const result = await currentWalletInstance.mintTokens(amount);
              console.log("Mint Transaction ID:", result);
              break;
            }
            case "burntokens": {
              const amount = BigInt(parseInt(args[0]));
              const result = await currentWalletInstance.burnTokens(amount);
              console.log("Burn Transaction ID:", result);
              break;
            }
            case "freezetokens": {
              const result = await currentWalletInstance.freezeTokens(args[0]);
              console.log("Freeze Result:", {
                impactedOutputIds: result.impactedOutputIds,
                impactedTokenAmount: result.impactedTokenAmount.toString(),
              });
              break;
            }
            case "unfreezetokens": {
              const result = await currentWalletInstance.unfreezeTokens(args[0]);
              console.log("Unfreeze Result:", {
                impactedOutputIds: result.impactedOutputIds,
                impactedTokenAmount: result.impactedTokenAmount.toString(),
              });
              break;
            }
            case "getissuertokenactivity": {
              const result = await currentWalletInstance.getIssuerTokenActivity();
              if (!result.transactions || result.transactions.length === 0) {
                console.log("No transactions found");
              }
              for (const transaction of result.transactions) {
                console.log(
                  `Token Activity - case: ${transaction.transaction?.$case} | operation type: ${transaction.transaction?.$case === "spark" ? transaction.transaction?.spark.operationType : transaction.transaction?.onChain.operationType}`,
                );
              }
              break;
            }
            case "announcetoken": {
              if (args.length < 5) {
                console.log(
                  "Usage: announcetoken <tokenName> <tokenTicker> <decimals> <maxSupply> <isFreezable>",
                );
                break;
              }
              const [tokenName, tokenTicker, decimals, maxSupply, isFreezable] =
                args;
              const result = await currentWalletInstance.announceTokenL1(
                tokenName,
                tokenTicker,
                parseInt(decimals),
                BigInt(maxSupply),
                isFreezable.toLowerCase() === "true",
              );
              console.log("Token Announcement Transaction ID:", result);
              break;
            }
            case "querytokentransactions": {
              if (args.length > 2) {
                console.log(
                  "Usage: querytokentransactions [tokenPublicKey] [tokenTransactionHash]",
                );
                break;
              }

              try {
                let tokenPublicKeys: string[];
                if (args.length === 0) {
                  const publicKey = await currentWalletInstance.getIdentityPublicKey();
                  tokenPublicKeys = [publicKey];
                } else {
                  tokenPublicKeys = [args[0]];
                }

                const tokenTransactionHashes = args[1] ? [args[1]] : undefined;

                const transactions = await currentWalletInstance.queryTokenTransactions(
                  tokenPublicKeys,
                  tokenTransactionHashes,
                );
                console.log("\nToken Transactions:");
                for (const tx of transactions) {
                  console.log("\nTransaction Details:");
                  console.log(`  Status: ${TokenTransactionStatus[tx.status]}`);

                  if (tx.tokenTransaction?.tokenInputs) {
                    const input = tx.tokenTransaction.tokenInputs;
                    if (input.$case === "mintInput") {
                      console.log("  Type: Mint");
                      console.log(
                        `  Issuer Public Key: ${hex.encode(input.mintInput.issuerPublicKey)}`,
                      );
                      console.log(
                        `  Timestamp: ${new Date(input.mintInput.issuerProvidedTimestamp * 1000).toISOString()}`,
                      );
                    } else if (input.$case === "transferInput") {
                      console.log("  Type: Transfer");
                      console.log(
                        `  Outputs to Spend: ${input.transferInput.outputsToSpend.length}`,
                      );
                    }
                  }

                  if (tx.tokenTransaction?.tokenOutputs) {
                    console.log("\n  Outputs:");
                    for (const output of tx.tokenTransaction.tokenOutputs) {
                      console.log(
                        `    Owner Public Key: ${hex.encode(output.ownerPublicKey)}`,
                      );
                      console.log(
                        `    Token Public Key: ${hex.encode(output.tokenPublicKey)}`,
                      );
                      console.log(
                        `    Token Amount: ${hex.encode(output.tokenAmount)}`,
                      );
                      if (output.withdrawBondSats !== undefined) {
                        console.log(
                          `    Withdraw Bond Sats: ${output.withdrawBondSats}`,
                        );
                      }
                      if (output.withdrawRelativeBlockLocktime !== undefined) {
                        console.log(
                          `    Withdraw Relative Block Locktime: ${output.withdrawRelativeBlockLocktime}`,
                        );
                      }
                      console.log("    ---");
                    }
                  }
                  console.log("----------------------------------------");
                }
              } catch (error) {
                console.error("Error querying token transactions:", error);
              }
              break;
          }
        }
      }
    } catch (error) {
      console.error("\n命令执行时发生错误:", error instanceof Error ? error.message : String(error));
      if (process.env.DEBUG === "true" && error instanceof Error && error.stack) {
        console.error(error.stack);
      }
    }
  }
}

// Helper function to list existing wallet files
function موجودWalletFiles(): string[] {
  if (!existsSync(WALLET_DATA_DIR)) {
    return [];
  }
  try {
    const files = fsSync.readdirSync(WALLET_DATA_DIR);
    return files.filter(file => file.endsWith('.json'));
  } catch (error) {
    console.error("无法读取钱包目录:", error);
    return [];
  }
}

runCLI().catch(err => {
  console.error("CLI 发生严重错误，即将退出:", err);
  process.exit(1);
});
