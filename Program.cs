using System;
using System.IO;
using System.Security.Cryptography;

class Program
{
    static void Main()
    {
        string directorioClaves = "CLAVES";
        Directory.CreateDirectory(directorioClaves);

        while (true)
        {
            Console.WriteLine("Seleccione una opción:");
            Console.WriteLine("1. Generar el par de claves");
            Console.WriteLine("2. Firmar el mensaje");
            Console.WriteLine("3. Verificar la firma");
            Console.WriteLine("4. Salir");
            string opcion = Console.ReadLine();

            switch (opcion)
            {
                case "1":
                    GenerarParClaves(directorioClaves);
                    break;
                case "2":
                    FirmarMensaje(directorioClaves);
                    break;
                case "3":
                    VerificarFirma(directorioClaves);
                    break;
                case "4":
                    return;
                default:
                    Console.WriteLine("Opción no válida.");
                    break;
            }
        }
    }

    static void GenerarParClaves(string directorioClaves)
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
        {
            RSAParameters clavePrivada = rsa.ExportParameters(true);
            RSAParameters clavePublica = rsa.ExportParameters(false);

            string carpetaClave = Path.Combine(directorioClaves, Guid.NewGuid().ToString());
            Directory.CreateDirectory(carpetaClave);

            File.WriteAllText(Path.Combine(carpetaClave, "clavePublica.xml"), ConvertirAStringXML(clavePublica));
            File.WriteAllText(Path.Combine(carpetaClave, "clavePrivada.xml"), ConvertirAStringXML(clavePrivada));

            Console.WriteLine($"Las claves se generaron correctamente y se guardaron en: {carpetaClave}");
        }
    }

    static void FirmarMensaje(string directorioClaves)
    {
        Console.WriteLine("Ingrese el mensaje que desea firmar:");
        string mensaje = Console.ReadLine();
        File.WriteAllText("mensaje.txt", mensaje);

        Console.WriteLine("Ingrese la ruta en donde se encuentra la clave privada:");
        string rutaClavePrivada = Console.ReadLine();

        try
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string clavePrivadaXml = File.ReadAllText(rutaClavePrivada);
            rsa.FromXmlString(clavePrivadaXml);

            byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
            byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            File.WriteAllBytes("firma.txt", firma);
            Console.WriteLine("El mensaje fue firmado con exito y guardado en 'firma.txt'");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }

    static void VerificarFirma(string directorioClaves)
    {
        string mensaje = File.ReadAllText("mensaje.txt");
        Console.WriteLine($"Mensaje que desea verificar: {mensaje}");

        Console.WriteLine("Ingrese la ruta en donde se encuentra la clave pública:");
        string rutaClavePublica = Console.ReadLine();

        try
        {
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            string clavePublicaXml = File.ReadAllText(rutaClavePublica);
            rsa.FromXmlString(clavePublicaXml);

            byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
            byte[] firma = File.ReadAllBytes("firma.txt");
            bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            if (verificado)
                Console.WriteLine("La firma es valida.");
            else
                Console.WriteLine("La firma es invalida.");
        }
        catch (Exception e)
        {
            Console.WriteLine($"Error: {e.Message}");
        }
    }

    static string ConvertirAStringXML(RSAParameters parametrosRSA)
    {
        using (var sw = new StringWriter())
        {
            var xs = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            xs.Serialize(sw, parametrosRSA);
            return sw.ToString();
        }
    }
}