using HandyControl.Controls;
using HandyControl.Data;
using HandyControl.Properties.Langs;
using HandyControl.Tools;
using RSA;
using System;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;

namespace Cap_RSA;

public partial class MainWindow : System.Windows.Window
{
    public MainWindow()
    {
        InitializeComponent();

        ConfigHelper.Instance.SetLang(System.Globalization.CultureInfo.CurrentCulture.Name);
    }

    #region Tab Verify
    /// <summary>
    /// Generate Public And Private Key
    /// </summary>
    private void btnGenerate_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            string publicKey = string.Empty, privateKey = string.Empty;
            
            Task.Run(() =>
            {
                // Generate Public And Private Key
                (publicKey, privateKey) = RSA_Cryptography.GenerateKeys();
            })
            .ContinueWith((t) =>
            {
                // Show Public And Private Key
                txtPublicKey.Document.Blocks.Clear();
                txtPublicKey.Document.Blocks.Add(new Paragraph(new Run(publicKey)));
                txtPrivateKey.Document.Blocks.Clear();
                txtPrivateKey.Document.Blocks.Add(new Paragraph(new Run(privateKey)));

                txtPrivateSign.Document.Blocks.Clear();
                txtPrivateSign.Document.Blocks.Add(new Paragraph(new Run(publicKey)));

                // Show Success Growl
                Growl.SuccessGlobal(new GrowlInfo
                {
                    Message = "RSA Keys Generated Successfully",
                    WaitTime = 3,
                    ShowCloseButton = true,
                    Type = InfoType.Success
                });
                btnGenerate.IsChecked = false;
            }, TaskScheduler.FromCurrentSynchronizationContext());
        }
        catch (Exception ex)
        {
            HandyControl.Controls.MessageBox.Show(ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// verify IsSignature valid
    /// </summary>
    private void btnVerifySignature_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var txtPublicKey = new TextRange(txtPrivateSign.Document.ContentStart, txtPrivateSign.Document.ContentEnd).Text;
            var publicSign = new TextRange(txtPublicSign.Document.ContentStart, txtPublicSign.Document.ContentEnd).Text;
            var plainText = txtPrivatePlainText.Text;
            
            if(string.IsNullOrWhiteSpace(txtPublicKey))
            {
                HandyControl.Controls.MessageBox.Show("Please Generate Public key", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(publicSign))
            {
                HandyControl.Controls.MessageBox.Show("Please Generate Public Sign", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(plainText))
            {
                HandyControl.Controls.MessageBox.Show("Please Fill Plain Text", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (RSA_Cryptography.ClientValidateSignature(plainText, publicSign, txtPublicKey))
                HandyControl.Controls.MessageBox.Show("Signature Is Valid", "Result", MessageBoxButton.OK, MessageBoxImage.Information);
            else
                HandyControl.Controls.MessageBox.Show("Signature Is not Valid", "Result", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            HandyControl.Controls.MessageBox.Show(ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// generate verify signature
    /// </summary>
    private void btnSignPublicTextPlain_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var privateKey = new TextRange(txtPrivateKey.Document.ContentStart, txtPrivateKey.Document.ContentEnd).Text;
            var plainText = txtPublicPlainText.Text;
            
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                HandyControl.Controls.MessageBox.Show("Please Generate Private key", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(plainText))
            {
                HandyControl.Controls.MessageBox.Show("Please Enter Public Plain Text", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var signRSA = RSA_Cryptography.VerifySignature(plainText, privateKey);
            txtPublicSign.Document.Blocks.Clear();
            txtPublicSign.Document.Blocks.Add(new Paragraph(new Run(signRSA)));
        }
        catch (Exception ex)
        {
            HandyControl.Controls.MessageBox.Show(ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Copy public key
    /// </summary>
    private void btnPublicKeyCopy_Click(object sender, RoutedEventArgs e)
    {
        var publicKey = new TextRange(txtPublicKey.Document.ContentStart, txtPublicKey.Document.ContentEnd).Text;
        Clipboard.SetText(publicKey);
    }
    /// <summary>
    /// Paste public key
    /// </summary>
    private void btnPublicKeyPaste_Click(object sender, RoutedEventArgs e)
    {
        txtPublicKey.Document.Blocks.Clear();
        txtPublicKey.Document.Blocks.Add(new Paragraph(new Run(Clipboard.GetText())));
    }

    /// <summary>
    /// Copy private key
    /// </summary>
    private void btnPrivateKeyCopy_Click(object sender, RoutedEventArgs e)
    {
        var privateKey = new TextRange(txtPrivateKey.Document.ContentStart, txtPrivateKey.Document.ContentEnd).Text;
        Clipboard.SetText(privateKey);
    }
    /// <summary>
    /// Paste private key
    /// </summary>
    private void btnPrivateKeyPaste_Click(object sender, RoutedEventArgs e)
    {
        txtPrivateKey.Document.Blocks.Clear();
        txtPrivateKey.Document.Blocks.Add(new Paragraph(new Run(Clipboard.GetText())));
    }

    private void txtPublicPlainText_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (txtPublicPlainText.Text.Equals("Private Text message to be signed"))
            return;
        
        btnSignPublicTextPlain_Click(sender, e);
    }
    #endregion

    #region Tab Encrypt And Decrypt
    /// <summary>
    /// Encryt text with public key
    /// </summary>
    private void Tab_btnEncryptTextPlain_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var publicKey = new TextRange(txtPublicKey.Document.ContentStart, txtPublicKey.Document.ContentEnd).Text;
            var plainText = Tab_txtPublicPlainText.Text;
            
            if (string.IsNullOrWhiteSpace(publicKey))
            {
                HandyControl.Controls.MessageBox.Show("Please Generate Public key", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(plainText))
            {
                HandyControl.Controls.MessageBox.Show("Please Enter Public Plain Text", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var encryptRSA = RSA_Cryptography.RsaEncryptWithPublic(plainText, publicKey);
            Tab_txtPublicSign.Document.Blocks.Clear();
            Tab_txtPublicSign.Document.Blocks.Add(new Paragraph(new Run(encryptRSA)));

            Tab_txtPrivateSignature.Text = encryptRSA;
        }
        catch (Exception ex)
        {
            HandyControl.Controls.MessageBox.Show(ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    private void Tab_txtPublicPlainText_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (Tab_txtPublicPlainText.Text.Equals("Public Text message to Encrypt"))
            return;

        Tab_btnEncryptTextPlain_Click(sender, e);
    }

    /// <summary>
    /// Decrypt text with private key
    /// </summary>
    private void Tab_btnDecryptTextPlain_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var privateKey = new TextRange(txtPrivateKey.Document.ContentStart, txtPrivateKey.Document.ContentEnd).Text;
            var plainText = Tab_txtPrivateSignature.Text;
            
            if (string.IsNullOrWhiteSpace(privateKey))
            {
                HandyControl.Controls.MessageBox.Show("Please Generate Public key", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }
            if (string.IsNullOrWhiteSpace(plainText))
            {
                HandyControl.Controls.MessageBox.Show("Please Enter Public Plain Text", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var decryptRSA = RSA_Cryptography.RsaDecryptWithPrivate(plainText, privateKey);
            Tab_txtPrivateSign.Document.Blocks.Clear();
            Tab_txtPrivateSign.Document.Blocks.Add(new Paragraph(new Run(decryptRSA)));
        }
        catch (Exception ex)
        {
            HandyControl.Controls.MessageBox.Show(ex.ToString(), "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
    #endregion
}
