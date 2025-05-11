import readline from 'readline';

// No longer augmenting readline.Interface as we are simplifying promptForPassword

export async function promptForPassword(promptText: string, rl: readline.Interface): Promise<string> {
  return new Promise((resolve) => {
    rl.question(promptText, (password) => {
      resolve(password);
    });
  });
}

export async function promptForConfirmation(promptText: string, rl: readline.Interface): Promise<boolean> {
  return new Promise((resolve) => {
    rl.question(`${promptText} (y/n): `, (answer) => {
      resolve(answer.toLowerCase() === 'y' || answer.toLowerCase() === 'yes');
    });
  });
}
