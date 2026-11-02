// =============================================================================
// TitanRescate.exe - Motor de recuperación de TITAN BLACKBOX.
//
// Se compila en el PC técnico con el compilador de .NET Framework que trae
// Windows (csc.exe, C# 5) y se ejecuta en WinPE (WinPE-NetFX). Construir\
// Compilar-Rescate.ps1 lo compila; el ancla de TITAN lo verifica por SHA-256.
//
// Reglas que este programa cumple SIEMPRE:
//   - El ORIGEN se abre solo con permiso de LECTURA (GENERIC_READ). Nunca se
//     escribe en un dispositivo (rutas \\.\...): se rechaza como destino.
//   - Las reconstrucciones experimentales (MBR) solo se hacen sobre ARCHIVOS
//     de imagen (copias de trabajo), nunca sobre discos.
//   - Nada se borra del origen.
//
// Subcomandos:
//   copiar       Copia un archivo por bloques con mapa reanudable (formato de
//                mapfile de GNU ddrescue), reintentos limitados y relleno de
//                zonas ilegibles; verifica SHA-256.
//   imagen       Igual, pero de un disco o volumen completo (o un rango) a un
//                archivo de imagen.
//   vhd          Añade el pie VHD "fijo" a una imagen para montarla en Windows
//                en solo lectura (diskpart attach vdisk readonly).
//   particiones  Lee MBR/GPT y busca sectores de arranque NTFS/exFAT/FAT32
//                (particiones perdidas). Solo lectura.
//   reconstruir-mbr  Escribe un MBR nuevo en una COPIA de imagen (guarda el
//                sector 0 original en .sector0.bak).
//   firmas       Recupera archivos por firma (carving) de un disco, volumen o
//                imagen: JPEG, PNG, GIF, PDF, ZIP/Office/OpenDocument, SQLite,
//                MP4/MOV.
//   salud        Salud del disco: registro SMART de NVMe o predicción de fallo.
//   info         Tamaño y sector de un disco/volumen/archivo.
//   sha256       SHA-256 de un archivo (admite rutas largas).
//
// Salida: líneas "TITAN_PROGRESO ..." en stderr y UNA línea
// "TITAN_RESULTADO {json}" en stdout. Códigos de salida: 0 bien,
// 1 operación con errores (ver JSON), 2 argumentos, 3 interrumpido (prueba),
// 4 rechazado por seguridad.
// =============================================================================
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

[assembly: System.Reflection.AssemblyTitle("TitanRescate")]
[assembly: System.Reflection.AssemblyDescription("Motor de recuperación de TITAN BLACKBOX")]
[assembly: System.Reflection.AssemblyVersion("1.0.0.0")]
// Destino .NET 4.8 (WinPE-NetFX): activa las rutas largas en System.IO
[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]

namespace Titan
{
    // -------------------------------------------------------------------------
    // Errores
    // -------------------------------------------------------------------------
    class ErrorLectura : Exception
    {
        public int Codigo;
        public ErrorLectura(int codigo, string msg) : base(msg) { Codigo = codigo; }
    }

    class ErrorEscritura : Exception
    {
        public int Codigo;
        public ErrorEscritura(int codigo, string msg) : base(msg) { Codigo = codigo; }
    }

    class Rechazo : Exception
    {
        public Rechazo(string msg) : base(msg) { }
    }

    static class Clasificador
    {
        // Categorías del pliego BLACKBOX
        public const string Inaccesible = "ARCHIVO_INACCESIBLE";
        public const string Permisos = "PROBLEMA_PERMISOS";
        public const string RutaLarga = "RUTA_DEMASIADO_LARGA";
        public const string Lectura = "ERROR_LECTURA";
        public const string Fisico = "DISCO_POSIBLE_FALLO_FISICO";
        public const string SinEspacio = "DESTINO_SIN_ESPACIO";
        public const string Integridad = "ERROR_INTEGRIDAD";
        public const string Parcial = "ARCHIVO_PARCIALMENTE_LEGIBLE";
        public const string Desconectado = "DISPOSITIVO_DESCONECTADO";
        public const string Otro = "OTRO";

        public static string Categoria(int w32)
        {
            switch (w32)
            {
                case 2: case 3: case 32: case 33: case 1920: return Inaccesible;
                case 5: case 1307: case 1314: return Permisos;
                case 206: case 161: case 123: return RutaLarga;
                case 23: case 27: case 30: case 121: case 1784: case 25: return Lectura;
                case 31: case 483: case 1117: case 1110: return Fisico;
                case 21: case 55: case 433: case 1167: case 1006: return Desconectado;
                case 39: case 112: return SinEspacio;
                default: return Otro;
            }
        }

        public static bool EsDesconexion(int w32)
        {
            return Categoria(w32) == Desconectado;
        }

        public static bool EsFisico(int w32)
        {
            string c = Categoria(w32);
            return c == Fisico || c == Lectura;
        }
    }

    // -------------------------------------------------------------------------
    // Llamadas nativas (solo Windows)
    // -------------------------------------------------------------------------
    static class Nat
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
        public const uint OPEN_EXISTING = 3, OPEN_ALWAYS = 4, CREATE_ALWAYS = 2;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(SafeFileHandle h, byte[] buf, int n, out int leidos, IntPtr ovl);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(SafeFileHandle h, byte[] buf, int n, out int escritos, IntPtr ovl);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFilePointerEx(SafeFileHandle h, long dist, out long nueva, uint metodo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetFileSizeEx(SafeFileHandle h, out long tam);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetEndOfFile(SafeFileHandle h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushFileBuffers(SafeFileHandle h);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DeviceIoControl(SafeFileHandle h, uint codigo, byte[] entrada, int tamEntrada, byte[] salida, int tamSalida, out int devueltos, IntPtr ovl);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateDirectoryW(string ruta, IntPtr sec);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetFileAttributesW(string ruta);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetDiskFreeSpaceExW(string dir, out ulong libre, out ulong total, out ulong totalLibre);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool MoveFileExW(string a, string b, uint flags);

        [DllImport("kernel32.dll")]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool OpenProcessToken(IntPtr proceso, uint acceso, out IntPtr token);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LookupPrivilegeValueW(string sistema, string nombre, out long luid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool AdjustTokenPrivileges(IntPtr token, bool desactivarTodos, ref TOKEN_PRIVILEGES nuevo, int tam, IntPtr previo, IntPtr tamPrevio);

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct TOKEN_PRIVILEGES
        {
            public int Cuenta;
            public long Luid;
            public int Atributos;
        }

        public static bool EsWindows
        {
            get { return Environment.OSVersion.Platform == PlatformID.Win32NT; }
        }

        static bool backupActivado;

        public static void ActivarBackupPrivilege()
        {
            if (backupActivado || !EsWindows) return;
            backupActivado = true;
            IntPtr token;
            if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out token)) return;
            long luid;
            if (!LookupPrivilegeValueW(null, "SeBackupPrivilege", out luid)) return;
            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.Cuenta = 1; tp.Luid = luid; tp.Atributos = 2;
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }

        // Prefijo \\?\ para rutas largas (C:\... -> \\?\C:\..., \\srv\x -> \\?\UNC\srv\x)
        public static string Larga(string ruta)
        {
            if (!EsWindows) return ruta;
            if (ruta.StartsWith(@"\\?\") || ruta.StartsWith(@"\\.\")) return ruta;
            if (ruta.Length >= 2 && ruta[1] == ':') return @"\\?\" + ruta;
            if (ruta.StartsWith(@"\\")) return @"\\?\UNC\" + ruta.Substring(2);
            return ruta;
        }

        public static bool EsDispositivo(string ruta)
        {
            return ruta.StartsWith(@"\\.\") || ruta.StartsWith(@"\\?\GLOBALROOT", StringComparison.OrdinalIgnoreCase)
                || ruta.StartsWith(@"\\?\Volume{", StringComparison.OrdinalIgnoreCase);
        }
    }

    // -------------------------------------------------------------------------
    // Fuentes de lectura (origen). Nunca escriben.
    // -------------------------------------------------------------------------
    interface IFuente : IDisposable
    {
        long Longitud { get; }
        int Sector { get; }
        string Estrategia { get; }
        // Lee exactamente n bytes en pos (o lanza ErrorLectura). Devuelve bytes leídos (< n solo al final).
        int Leer(long pos, byte[] buf, int n);
    }

    class FuenteWindows : IFuente
    {
        SafeFileHandle h;
        long longitud;
        int sector = 512;
        string estrategia = "normal";
        public long Longitud { get { return longitud; } }
        public int Sector { get { return sector; } }
        public string Estrategia { get { return estrategia; } }

        public FuenteWindows(string ruta)
        {
            bool dispositivo = Nat.EsDispositivo(ruta);
            string r = dispositivo ? ruta : Nat.Larga(ruta);
            uint share = Nat.FILE_SHARE_READ | Nat.FILE_SHARE_WRITE | Nat.FILE_SHARE_DELETE;
            h = Nat.CreateFileW(r, Nat.GENERIC_READ, share, IntPtr.Zero, Nat.OPEN_EXISTING, dispositivo ? 0 : Nat.FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
            if (h.IsInvalid)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == 5 && !dispositivo)
                {
                    // Estrategia alternativa: semántica de copia de seguridad (SeBackupPrivilege).
                    // Sigue siendo SOLO LECTURA.
                    Nat.ActivarBackupPrivilege();
                    h = Nat.CreateFileW(r, Nat.GENERIC_READ, share, IntPtr.Zero, Nat.OPEN_EXISTING, Nat.FILE_FLAG_BACKUP_SEMANTICS | Nat.FILE_FLAG_SEQUENTIAL_SCAN, IntPtr.Zero);
                    if (h.IsInvalid) e = Marshal.GetLastWin32Error();
                    else estrategia = "backup_semantics";
                }
                if (h.IsInvalid) throw new ErrorLectura(e, "No se pudo abrir el origen (Win32 " + e + ")");
            }
            if (dispositivo)
            {
                longitud = Dispositivo.Longitud(h);
                sector = Dispositivo.TamSector(h);
            }
            else
            {
                long t;
                if (!Nat.GetFileSizeEx(h, out t)) throw new ErrorLectura(Marshal.GetLastWin32Error(), "No se pudo leer el tamaño");
                longitud = t;
            }
        }

        public int Leer(long pos, byte[] buf, int n)
        {
            long nueva;
            if (!Nat.SetFilePointerEx(h, pos, out nueva, 0)) { int e = Marshal.GetLastWin32Error(); throw new ErrorLectura(e, "Posicionamiento " + e); }
            int total = 0;
            while (total < n)
            {
                int leidos;
                byte[] destino = buf;
                if (total > 0)
                {
                    destino = new byte[n - total];
                }
                if (!Nat.ReadFile(h, destino, n - total, out leidos, IntPtr.Zero))
                {
                    int e = Marshal.GetLastWin32Error();
                    if (e == 38) break; // fin de archivo
                    throw new ErrorLectura(e, "Lectura en " + pos + " (Win32 " + e + ")");
                }
                if (leidos == 0) break;
                if (total > 0) Buffer.BlockCopy(destino, 0, buf, total, leidos);
                total += leidos;
            }
            return total;
        }

        public void Dispose() { if (h != null) h.Dispose(); }
    }

    // Fuente administrada (para pruebas fuera de Windows y archivos simples)
    class FuenteGestionada : IFuente
    {
        FileStream fs;
        public long Longitud { get { return fs.Length; } }
        public int Sector { get { return 512; } }
        public string Estrategia { get { return "normal"; } }
        public FuenteGestionada(string ruta)
        {
            try { fs = new FileStream(ruta, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete); }
            catch (UnauthorizedAccessException ex) { throw new ErrorLectura(5, ex.Message); }
            catch (FileNotFoundException ex) { throw new ErrorLectura(2, ex.Message); }
            catch (DirectoryNotFoundException ex) { throw new ErrorLectura(3, ex.Message); }
            catch (PathTooLongException ex) { throw new ErrorLectura(206, ex.Message); }
            catch (IOException ex) { throw new ErrorLectura(32, ex.Message); }
        }
        public bool Estricta = false; // PRUEBA: exige lecturas alineadas, como un dispositivo de Windows
        public int Leer(long pos, byte[] buf, int n)
        {
            if (Estricta && (pos % 512 != 0 || n % 512 != 0)) throw new ErrorLectura(87, "Lectura no alineada en dispositivo (pos " + pos + ", " + n + " bytes)");
            fs.Position = pos;
            int total = 0;
            while (total < n)
            {
                int r = fs.Read(buf, total, n - total);
                if (r <= 0) break;
                total += r;
            }
            return total;
        }
        public void Dispose() { fs.Dispose(); }
    }

    // Lectura de DISCOS y VOLÚMENES: Windows exige que la posición y la longitud
    // de cada lectura sean múltiplos del tamaño de sector. Esta envoltura lee el
    // tramo alineado que contiene lo pedido y copia solo la parte solicitada.
    // Sigue siendo solo lectura.
    class FuenteAlineada : IFuente
    {
        IFuente interior;
        int sector;
        public long Longitud { get { return interior.Longitud; } }
        public int Sector { get { return interior.Sector; } }
        public string Estrategia { get { return interior.Estrategia; } }
        public FuenteAlineada(IFuente f) { interior = f; sector = Math.Max(512, f.Sector); }
        public int Leer(long pos, byte[] buf, int n)
        {
            if (n <= 0) return 0;
            if (pos % sector == 0 && n % sector == 0) return interior.Leer(pos, buf, n);
            long ini = pos - (pos % sector);
            long fin = (pos + n + sector - 1) / sector * sector;
            long lon = interior.Longitud;
            if (lon > 0 && fin > lon) fin = Math.Max(ini + sector, lon);
            byte[] tmp = new byte[fin - ini];
            int r = interior.Leer(ini, tmp, tmp.Length);
            int salto = (int)(pos - ini);
            int util = Math.Max(0, Math.Min(n, r - salto));
            if (util > 0) Buffer.BlockCopy(tmp, salto, buf, 0, util);
            return util;
        }
        public void Dispose() { interior.Dispose(); }
    }

    // Envoltura de PRUEBA: simula sectores ilegibles. Solo se activa con
    // --prueba-fallos y la variable de entorno TITAN_MODO_PRUEBA=1.
    class FuenteConFallos : IFuente
    {
        IFuente interior;
        List<long[]> zonas = new List<long[]>(); // {inicio, fin, fallosRestantes(-1 = siempre)}
        public long Longitud { get { return interior.Longitud; } }
        public int Sector { get { return interior.Sector; } }
        public string Estrategia { get { return interior.Estrategia; } }
        public FuenteConFallos(IFuente f, string espec)
        {
            interior = f;
            foreach (string parte in espec.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] p = parte.Split(':');
                long ini = long.Parse(p[0], CultureInfo.InvariantCulture);
                long lon = long.Parse(p[1], CultureInfo.InvariantCulture);
                long k = p.Length > 2 ? long.Parse(p[2], CultureInfo.InvariantCulture) : -1;
                zonas.Add(new long[] { ini, ini + lon, k });
            }
        }
        public int Leer(long pos, byte[] buf, int n)
        {
            foreach (long[] z in zonas)
            {
                if (pos < z[1] && pos + n > z[0] && z[2] != 0)
                {
                    if (z[2] > 0) z[2]--;
                    throw new ErrorLectura(23, "Error CRC simulado en " + pos);
                }
            }
            return interior.Leer(pos, buf, n);
        }
        public void Dispose() { interior.Dispose(); }
    }

    static class Fuentes
    {
        public static IFuente Abrir(string ruta, string fallos)
        {
            IFuente f;
            bool prueba = Environment.GetEnvironmentVariable("TITAN_MODO_PRUEBA") == "1";
            bool simularDispositivo = prueba && Environment.GetEnvironmentVariable("TITAN_PRUEBA_DISPOSITIVO") == "1";
            if (Nat.EsWindows) f = new FuenteWindows(ruta);
            else
            {
                FuenteGestionada g = new FuenteGestionada(ruta);
                g.Estricta = simularDispositivo;
                f = g;
            }
            bool sinAlinear = prueba && Environment.GetEnvironmentVariable("TITAN_PRUEBA_SIN_ALINEAR") == "1";
            if ((Nat.EsDispositivo(ruta) || simularDispositivo) && !sinAlinear) f = new FuenteAlineada(f);
            if (!string.IsNullOrEmpty(fallos))
            {
                if (Environment.GetEnvironmentVariable("TITAN_MODO_PRUEBA") != "1")
                    throw new Rechazo("--prueba-fallos solo se admite en modo de prueba (TITAN_MODO_PRUEBA=1).");
                f = new FuenteConFallos(f, fallos);
            }
            return f;
        }
    }

    // -------------------------------------------------------------------------
    // Información de dispositivos (IOCTL)
    // -------------------------------------------------------------------------
    static class Dispositivo
    {
        const uint IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C;
        const uint IOCTL_DISK_GET_DRIVE_GEOMETRY_EX = 0x000700A0;

        public static long Longitud(SafeFileHandle h)
        {
            byte[] sal = new byte[8];
            int dev;
            if (!Nat.DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, null, 0, sal, 8, out dev, IntPtr.Zero))
                throw new ErrorLectura(Marshal.GetLastWin32Error(), "No se pudo leer el tamaño del dispositivo");
            return BitConverter.ToInt64(sal, 0);
        }

        public static int TamSector(SafeFileHandle h)
        {
            byte[] sal = new byte[256];
            int dev;
            if (!Nat.DeviceIoControl(h, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, null, 0, sal, sal.Length, out dev, IntPtr.Zero)) return 512;
            int bps = BitConverter.ToInt32(sal, 20); // DISK_GEOMETRY.BytesPerSector
            return (bps == 512 || bps == 4096) ? bps : 512;
        }
    }

    // -------------------------------------------------------------------------
    // Destino de escritura (solo archivos; nunca dispositivos)
    // -------------------------------------------------------------------------
    class Destino : IDisposable
    {
        SafeFileHandle h;
        FileStream fs;
        public string Ruta;

        public Destino(string ruta, long longitud)
        {
            if (Nat.EsDispositivo(ruta)) throw new Rechazo("El destino no puede ser un dispositivo.");
            Ruta = ruta;
            Util.CrearCarpeta(Util.Dir(ruta));
            if (Nat.EsWindows)
            {
                h = Nat.CreateFileW(Nat.Larga(ruta), Nat.GENERIC_READ | Nat.GENERIC_WRITE, Nat.FILE_SHARE_READ, IntPtr.Zero, Nat.OPEN_ALWAYS, Nat.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (h.IsInvalid) { int e = Marshal.GetLastWin32Error(); throw new ErrorEscritura(e, "No se pudo crear el destino (Win32 " + e + ")"); }
                long actual;
                Nat.GetFileSizeEx(h, out actual);
                if (actual != longitud)
                {
                    long n;
                    if (!Nat.SetFilePointerEx(h, longitud, out n, 0) || !Nat.SetEndOfFile(h))
                    { int e = Marshal.GetLastWin32Error(); throw new ErrorEscritura(e, "No se pudo reservar el destino (Win32 " + e + ")"); }
                }
            }
            else
            {
                fs = new FileStream(ruta, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
                if (fs.Length != longitud) fs.SetLength(longitud);
            }
        }

        public void Escribir(long pos, byte[] buf, int n)
        {
            if (h != null)
            {
                long nueva;
                if (!Nat.SetFilePointerEx(h, pos, out nueva, 0)) { int e = Marshal.GetLastWin32Error(); throw new ErrorEscritura(e, "Posicionamiento destino " + e); }
                int escritos;
                if (!Nat.WriteFile(h, buf, n, out escritos, IntPtr.Zero) || escritos != n)
                {
                    int e = Marshal.GetLastWin32Error();
                    throw new ErrorEscritura(e == 0 ? 112 : e, "Escritura en destino (Win32 " + e + ")");
                }
            }
            else
            {
                fs.Position = pos;
                try { fs.Write(buf, 0, n); }
                catch (IOException ex) { throw new ErrorEscritura(112, ex.Message); }
            }
        }

        public void Vaciar()
        {
            if (h != null) Nat.FlushFileBuffers(h); else fs.Flush(true);
        }

        public void Dispose()
        {
            if (h != null) h.Dispose();
            if (fs != null) fs.Dispose();
        }
    }

    // -------------------------------------------------------------------------
    // Utilidades
    // -------------------------------------------------------------------------
    static class Util
    {
        // Carpeta padre sin las comprobaciones de longitud de System.IO
        public static string Dir(string ruta)
        {
            if (string.IsNullOrEmpty(ruta)) return null;
            string r = ruta.TrimEnd('\\', '/');
            int i = Math.Max(r.LastIndexOf('\\'), r.LastIndexOf('/'));
            if (i <= 0) return null;
            string d = r.Substring(0, i);
            if (d.Length == 2 && d[1] == ':') return d + "\\";
            return d;
        }

        static bool EsRaiz(string dir)
        {
            string d = dir;
            if (d.StartsWith(@"\\?\")) d = d.Substring(4);
            d = d.TrimEnd('\\', '/');
            return d.Length == 0 || (d.Length == 2 && d[1] == ':');
        }

        public static void CrearCarpeta(string dir)
        {
            if (string.IsNullOrEmpty(dir)) return;
            if (!Nat.EsWindows) { Directory.CreateDirectory(dir); return; }
            if (EsRaiz(dir)) return;
            string l = Nat.Larga(dir);
            if (Nat.GetFileAttributesW(l) != 0xFFFFFFFF) return;
            string padre = Dir(dir);
            if (!string.IsNullOrEmpty(padre) && padre != dir) CrearCarpeta(padre);
            if (!Nat.CreateDirectoryW(l, IntPtr.Zero))
            {
                int e = Marshal.GetLastWin32Error();
                if (e != 183) throw new ErrorEscritura(e, "No se pudo crear la carpeta " + dir + " (Win32 " + e + ")");
            }
        }

        public static bool Existe(string ruta)
        {
            if (!Nat.EsWindows) return File.Exists(ruta);
            uint a = Nat.GetFileAttributesW(Nat.Larga(ruta));
            return a != 0xFFFFFFFF && (a & 0x10) == 0;
        }

        public static long EspacioLibre(string dir)
        {
            if (!Nat.EsWindows)
            {
                try { return new DriveInfo(Path.GetPathRoot(Path.GetFullPath(dir ?? "."))).AvailableFreeSpace; } catch { return long.MaxValue; }
            }
            ulong libre, total, tl;
            string d = dir;
            while (!string.IsNullOrEmpty(d) && Nat.GetFileAttributesW(Nat.Larga(d)) == 0xFFFFFFFF) d = Dir(d);
            if (string.IsNullOrEmpty(d)) return long.MaxValue;
            if (!d.EndsWith("\\")) d = d + "\\";
            if (!Nat.GetDiskFreeSpaceExW(d, out libre, out total, out tl)) return long.MaxValue;
            return (long)libre;
        }

        public static void Mover(string a, string b)
        {
            if (Nat.EsWindows)
            {
                if (!Nat.MoveFileExW(Nat.Larga(a), Nat.Larga(b), 1 | 8)) // REPLACE_EXISTING | WRITE_THROUGH
                { int e = Marshal.GetLastWin32Error(); throw new ErrorEscritura(e, "No se pudo mover " + a + " (Win32 " + e + ")"); }
            }
            else
            {
                if (File.Exists(b)) File.Delete(b);
                File.Move(a, b);
            }
        }

        public static void EscribirTexto(string ruta, string texto)
        {
            // Escritura atómica: temporal + reemplazo
            string tmp = ruta + ".tmp";
            byte[] datos = new UTF8Encoding(false).GetBytes(texto);
            using (Destino d = new Destino(tmp, datos.Length))
            {
                d.Escribir(0, datos, datos.Length);
                d.Vaciar();
            }
            Mover(tmp, ruta);
        }

        public static string LeerTexto(string ruta)
        {
            using (IFuente f = Fuentes.Abrir(ruta, null))
            {
                byte[] b = new byte[f.Longitud];
                int n = f.Leer(0, b, b.Length);
                return new UTF8Encoding(false).GetString(b, 0, n);
            }
        }

        public static string Hex(byte[] h)
        {
            StringBuilder sb = new StringBuilder(h.Length * 2);
            foreach (byte x in h) sb.Append(x.ToString("X2"));
            return sb.ToString();
        }

        // SHA-256 de una fuente completa. Lanza ErrorLectura si no se puede leer entera.
        public static string Sha256(IFuente f)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] buf = new byte[1 << 20];
                long pos = 0;
                while (pos < f.Longitud)
                {
                    int n = (int)Math.Min(buf.Length, f.Longitud - pos);
                    int r = f.Leer(pos, buf, n);
                    if (r <= 0) throw new ErrorLectura(38, "Fin inesperado");
                    sha.TransformBlock(buf, 0, r, null, 0);
                    pos += r;
                }
                sha.TransformFinalBlock(buf, 0, 0);
                return Hex(sha.Hash);
            }
        }

        public static string Sha256Archivo(string ruta)
        {
            using (IFuente f = Fuentes.Abrir(ruta, null)) return Sha256(f);
        }

        public static uint BE32(byte[] b, int o) { return (uint)(b[o] << 24 | b[o + 1] << 16 | b[o + 2] << 8 | b[o + 3]); }
        public static ushort BE16(byte[] b, int o) { return (ushort)(b[o] << 8 | b[o + 1]); }
        public static ulong BE64(byte[] b, int o) { return ((ulong)BE32(b, o) << 32) | BE32(b, o + 4); }
        public static void PonBE32(byte[] b, int o, uint v) { b[o] = (byte)(v >> 24); b[o + 1] = (byte)(v >> 16); b[o + 2] = (byte)(v >> 8); b[o + 3] = (byte)v; }
        public static void PonBE64(byte[] b, int o, ulong v) { PonBE32(b, o, (uint)(v >> 32)); PonBE32(b, o + 4, (uint)v); }
        public static void PonBE16(byte[] b, int o, ushort v) { b[o] = (byte)(v >> 8); b[o + 1] = (byte)v; }

        public static void Progreso(string texto)
        {
            try { Console.Error.WriteLine("TITAN_PROGRESO " + texto); } catch { }
        }
    }

    // -------------------------------------------------------------------------
    // JSON mínimo
    // -------------------------------------------------------------------------
    class Json
    {
        StringBuilder sb = new StringBuilder();
        bool primero = true;
        public Json() { sb.Append('{'); }
        void Clave(string k) { if (!primero) sb.Append(','); primero = false; sb.Append('"').Append(Esc(k)).Append("\":"); }
        public Json S(string k, string v) { Clave(k); if (v == null) sb.Append("null"); else sb.Append('"').Append(Esc(v)).Append('"'); return this; }
        public Json N(string k, long v) { Clave(k); sb.Append(v.ToString(CultureInfo.InvariantCulture)); return this; }
        public Json B(string k, bool v) { Clave(k); sb.Append(v ? "true" : "false"); return this; }
        public Json Crudo(string k, string json) { Clave(k); sb.Append(json); return this; }
        public override string ToString() { return sb.ToString() + "}"; }
        public static string Esc(string s)
        {
            StringBuilder r = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': r.Append("\\\""); break;
                    case '\\': r.Append("\\\\"); break;
                    case '\n': r.Append("\\n"); break;
                    case '\r': r.Append("\\r"); break;
                    case '\t': r.Append("\\t"); break;
                    default:
                        // Solo ASCII en la salida: la consola de WinPE/PowerShell usa otra página de códigos
                        if (c < 0x20 || c > 0x7E) r.Append("\\u").Append(((int)c).ToString("x4")); else r.Append(c);
                        break;
                }
            }
            return r.ToString();
        }
        public static string Lista(List<string> objetos)
        {
            return "[" + string.Join(",", objetos.ToArray()) + "]";
        }
    }

    // -------------------------------------------------------------------------
    // Mapa de recuperación, compatible con el "mapfile" de GNU ddrescue:
    //   # comentarios
    //   <pos_actual> <estado_actual> <pasada>
    //   <pos> <tamaño> <estado>     ('?' sin intentar, '*' fallo sin recortar,
    //                                '/' fallo sin raspar, '-' sector malo, '+' bien)
    // -------------------------------------------------------------------------
    class Bloque
    {
        public long Pos, Tam; public char Estado;
        public Bloque(long p, long t, char e) { Pos = p; Tam = t; Estado = e; }
        public long Fin { get { return Pos + Tam; } }
    }

    class Mapa
    {
        public long Longitud;
        public List<Bloque> Bloques = new List<Bloque>();
        public long PosActual;
        public char EstadoActual = '?';
        public int Pasada = 1;
        public Dictionary<string, string> Meta = new Dictionary<string, string>();

        public Mapa(long longitud)
        {
            Longitud = longitud;
            if (longitud > 0) Bloques.Add(new Bloque(0, longitud, '?'));
        }

        public void Marcar(long pos, long tam, char estado)
        {
            if (tam <= 0) return;
            long fin = pos + tam;
            List<Bloque> nuevos = new List<Bloque>();
            foreach (Bloque b in Bloques)
            {
                if (b.Fin <= pos || b.Pos >= fin) { nuevos.Add(b); continue; }
                if (b.Pos < pos) nuevos.Add(new Bloque(b.Pos, pos - b.Pos, b.Estado));
                if (b.Fin > fin) nuevos.Add(new Bloque(fin, b.Fin - fin, b.Estado));
            }
            nuevos.Add(new Bloque(pos, tam, estado));
            nuevos.Sort(delegate(Bloque a, Bloque c) { return a.Pos.CompareTo(c.Pos); });
            // fusionar contiguos del mismo estado
            List<Bloque> f = new List<Bloque>();
            foreach (Bloque b in nuevos)
            {
                if (f.Count > 0 && f[f.Count - 1].Estado == b.Estado && f[f.Count - 1].Fin == b.Pos) f[f.Count - 1].Tam += b.Tam;
                else f.Add(new Bloque(b.Pos, b.Tam, b.Estado));
            }
            Bloques = f;
        }

        public long Bytes(char estado)
        {
            long t = 0;
            foreach (Bloque b in Bloques) if (b.Estado == estado) t += b.Tam;
            return t;
        }

        public List<Bloque> Con(char estado)
        {
            List<Bloque> l = new List<Bloque>();
            foreach (Bloque b in Bloques) if (b.Estado == estado) l.Add(new Bloque(b.Pos, b.Tam, b.Estado));
            return l;
        }

        public bool Completo { get { return Bytes('+') == Longitud; } }

        public string Texto()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("# Mapfile. Created by TitanRescate 1.0 (formato de GNU ddrescue)\n");
            foreach (KeyValuePair<string, string> kv in Meta) sb.Append("# titan-").Append(kv.Key).Append(": ").Append(kv.Value).Append('\n');
            sb.Append("# current_pos  current_status  current_pass\n");
            sb.Append("0x").Append(PosActual.ToString("X8")).Append("     ").Append(EstadoActual).Append("               ").Append(Pasada).Append('\n');
            sb.Append("#      pos        size  status\n");
            foreach (Bloque b in Bloques)
                sb.Append("0x").Append(b.Pos.ToString("X8")).Append("  0x").Append(b.Tam.ToString("X8")).Append("  ").Append(b.Estado).Append('\n');
            return sb.ToString();
        }

        public void Guardar(string ruta) { Util.EscribirTexto(ruta, Texto()); }

        static long Num(string s)
        {
            s = s.Trim();
            if (s.StartsWith("0x") || s.StartsWith("0X")) return long.Parse(s.Substring(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return long.Parse(s, CultureInfo.InvariantCulture);
        }

        public static Mapa Cargar(string ruta, long longitudEsperada)
        {
            string texto = Util.LeerTexto(ruta);
            Mapa m = new Mapa(0);
            bool estadoLeido = false;
            foreach (string linea0 in texto.Split('\n'))
            {
                string linea = linea0.Trim();
                if (linea.Length == 0) continue;
                if (linea.StartsWith("#"))
                {
                    if (linea.StartsWith("# titan-"))
                    {
                        int dp = linea.IndexOf(": ");
                        if (dp > 0) m.Meta[linea.Substring(8, dp - 8)] = linea.Substring(dp + 2);
                    }
                    continue;
                }
                string[] p = linea.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (!estadoLeido)
                {
                    m.PosActual = Num(p[0]); m.EstadoActual = p[1][0]; m.Pasada = p.Length > 2 ? int.Parse(p[2], CultureInfo.InvariantCulture) : 1;
                    estadoLeido = true; continue;
                }
                m.Bloques.Add(new Bloque(Num(p[0]), Num(p[1]), p[2][0]));
            }
            long total = 0, esperado = 0;
            foreach (Bloque b in m.Bloques)
            {
                if (b.Pos != esperado) throw new InvalidDataException("Mapa con huecos o solapes");
                if ("?*/-+".IndexOf(b.Estado) < 0) throw new InvalidDataException("Estado desconocido en el mapa");
                esperado = b.Fin; total += b.Tam;
            }
            if (total != longitudEsperada) throw new InvalidDataException("El mapa no corresponde al tamaño del origen (" + total + " vs " + longitudEsperada + ")");
            m.Longitud = total;
            return m;
        }
    }

    // -------------------------------------------------------------------------
    // Motor de copia adaptativa (archivos y discos)
    // -------------------------------------------------------------------------
    class Opciones
    {
        public int Bloque = 1 << 20;        // 1 MiB en la primera pasada
        public int Minimo = 4096;           // tamaño de "raspado" de zonas malas
        public int Reintentos = 2;          // pasadas extra sobre sectores malos
        public int EsperaMs = 500;
        public bool Rapido = false;         // solo primera pasada (disco fallando)
        public int MaxErroresFisicos = 64;  // tras esto se deja de insistir
        public bool VerificarOrigen = true; // releer el origen para el SHA si hizo falta
        public long CortarTras = -1;        // PRUEBA: interrumpir tras N bytes escritos
        public long Margen = 64L << 20;     // espacio libre que se deja en el destino
    }

    class ResultadoCopia
    {
        public string Estado = "ERROR_RECUPERACION";
        public string Categoria = "";
        public int CodigoWin32;
        public string Mensaje = "";
        public long Tamano, BytesOk, BytesMalos, BytesPendientes;
        public string HashOrigen, HashDestino;
        public int Lecturas, Errores, Reanudado;
        public bool Fisico;
        public string Estrategia = "normal";
        public string Pasadas = "";
        public bool Interrumpido;
    }

    class Motor
    {
        IFuente src; Destino dst; Mapa mapa; string rutaMapa; Opciones op;
        public ResultadoCopia R = new ResultadoCopia();
        SHA256 shaSec; long posSec; bool secValido = true;
        long escritosEstaVez;
        DateTime ultimoGuardado = DateTime.UtcNow;
        int erroresConsecutivos;
        byte[] buf;

        public Motor(IFuente s, Destino d, Mapa m, string rm, Opciones o)
        {
            src = s; dst = d; mapa = m; rutaMapa = rm; op = o;
            buf = new byte[Math.Max(o.Bloque, o.Minimo)];
            if (m.Longitud == 0 || (m.Bytes('+') == 0 && m.Bloques.Count == 1)) shaSec = SHA256.Create();
            else { secValido = false; R.Reanudado = 1; }
        }

        void Guardar(bool forzar)
        {
            if (forzar || (DateTime.UtcNow - ultimoGuardado).TotalSeconds >= 2)
            {
                mapa.Guardar(rutaMapa);
                ultimoGuardado = DateTime.UtcNow;
            }
        }

        // Lee y escribe [pos, pos+n). Devuelve true si se leyó bien.
        bool Intentar(long pos, int n, char estadoFallo)
        {
            R.Lecturas++;
            int r;
            try { r = src.Leer(pos, buf, n); }
            catch (ErrorLectura e)
            {
                R.Errores++; erroresConsecutivos++;
                R.CodigoWin32 = e.Codigo;
                if (Clasificador.EsFisico(e.Codigo) && R.Errores >= 8) R.Fisico = true;
                if (Clasificador.EsDesconexion(e.Codigo)) throw;
                mapa.Marcar(pos, n, estadoFallo);
                secValido = false;
                return false;
            }
            if (r < n)
            {
                // El origen se acortó: lo leído vale, el resto es ilegible
                if (r > 0) { dst.Escribir(pos, buf, r); mapa.Marcar(pos, r, '+'); }
                mapa.Marcar(pos + r, n - r, '-');
                secValido = false;
                return false;
            }
            dst.Escribir(pos, buf, n);
            mapa.Marcar(pos, n, '+');
            erroresConsecutivos = 0;
            if (secValido && shaSec != null && pos == posSec) { shaSec.TransformBlock(buf, 0, n, null, 0); posSec += n; }
            else secValido = false;
            escritosEstaVez += n;
            if (op.CortarTras >= 0 && escritosEstaVez >= op.CortarTras)
            {
                Guardar(true);
                R.Interrumpido = true;
                throw new OperationCanceledException("Interrupción de prueba");
            }
            Guardar(false);
            return true;
        }

        public void Ejecutar()
        {
            try { EjecutarPasadas(); }
            finally
            {
                // Pase lo que pase (desconexión, destino lleno...), el mapa queda guardado
                try { dst.Vaciar(); } catch { }
                try { mapa.Guardar(rutaMapa); } catch { }
            }
            if (shaSec != null) shaSec.TransformFinalBlock(new byte[0], 0, 0);
        }

        void EjecutarPasadas()
        {
            long total = mapa.Longitud;
            // Pasada 1: copia por bloques grandes; ante un error se salta adelante
            // (las zonas saltadas quedan '?' y se intentan después hacia atrás).
            mapa.EstadoActual = '?'; mapa.Pasada = 1;
            List<Bloque> pendientes = mapa.Con('?');
            R.Pasadas = "1";
            foreach (Bloque b in pendientes)
            {
                long pos = b.Pos;
                while (pos < b.Fin)
                {
                    int n = (int)Math.Min(op.Bloque, b.Fin - pos);
                    mapa.PosActual = pos;
                    if (Intentar(pos, n, '*')) { pos += n; continue; }
                    // Error: saltar más lejos cuanto más errores seguidos (sin pasarse del bloque)
                    long salto = n;
                    if (erroresConsecutivos > 2)
                    {
                        long extra = Math.Min((long)op.Bloque << Math.Min(erroresConsecutivos - 2, 6), 64L << 20);
                        salto = Math.Min(n + extra, b.Fin - pos);
                    }
                    pos += salto;
                    Util.Progreso("copia " + pos + " " + total + " errores " + R.Errores);
                }
            }
            // Pasada 2: zonas saltadas ('?'), hacia atrás, a bloques pequeños
            List<Bloque> saltadas = mapa.Con('?');
            if (saltadas.Count > 0 && !(op.Rapido && R.Fisico))
            {
                R.Pasadas += ",2";
                mapa.Pasada = 2;
                for (int i = saltadas.Count - 1; i >= 0; i--)
                {
                    Bloque b = saltadas[i];
                    long fin = b.Fin;
                    while (fin > b.Pos)
                    {
                        int n = (int)Math.Min(op.Bloque, fin - b.Pos);
                        long pos = fin - n;
                        if (!Intentar(pos, n, '*')) { }
                        fin = pos;
                        if (R.Fisico && R.Errores > op.MaxErroresFisicos) break;
                    }
                }
            }
            if (!op.Rapido)
            {
                // Pasada 3: recortar/raspar las zonas fallidas sector a sector
                List<Bloque> fallidas = mapa.Con('*');
                if (fallidas.Count > 0)
                {
                    R.Pasadas += ",3";
                    mapa.EstadoActual = '/'; mapa.Pasada = 3;
                    foreach (Bloque b in fallidas)
                    {
                        for (long pos = b.Pos; pos < b.Fin; pos += op.Minimo)
                        {
                            if (R.Fisico && R.Errores > op.MaxErroresFisicos) { mapa.Marcar(pos, b.Fin - pos, '-'); break; }
                            int n = (int)Math.Min(op.Minimo, b.Fin - pos);
                            Intentar(pos, n, '-');
                        }
                    }
                }
                // Pasada 4: reintentos limitados de sectores malos, con espera
                for (int k = 0; k < op.Reintentos && mapa.Bytes('-') > 0; k++)
                {
                    if (R.Fisico && R.Errores > op.MaxErroresFisicos) break;
                    R.Pasadas += ",4";
                    mapa.EstadoActual = '-'; mapa.Pasada = 4 + k;
                    Thread.Sleep(op.EsperaMs);
                    foreach (Bloque b in mapa.Con('-'))
                    {
                        for (long pos = b.Pos; pos < b.Fin; pos += op.Minimo)
                        {
                            int n = (int)Math.Min(op.Minimo, b.Fin - pos);
                            Intentar(pos, n, '-');
                        }
                    }
                }
            }
            else
            {
                // Modo rápido (disco con fallos): las zonas fallidas quedan como malas
                foreach (Bloque b in mapa.Con('*')) mapa.Marcar(b.Pos, b.Tam, '-');
            }
            mapa.EstadoActual = '+';
        }

        public string HashSecuencial()
        {
            if (shaSec == null || !secValido || posSec != mapa.Longitud) return null;
            return Util.Hex(shaSec.Hash);
        }
    }

    // -------------------------------------------------------------------------
    // Subcomandos
    // -------------------------------------------------------------------------
    static class Comandos
    {
        static string Arg(Dictionary<string, string> a, string k, string def)
        {
            string v;
            return a.TryGetValue(k, out v) ? v : def;
        }

        static string Normal(string r)
        {
            if (r.StartsWith(@"\\?\")) r = r.Substring(4);
            return r.Replace('/', '\\').TrimEnd('\\');
        }

        static Opciones LeerOpciones(Dictionary<string, string> a)
        {
            Opciones o = new Opciones();
            o.Bloque = int.Parse(Arg(a, "bloque", o.Bloque.ToString()), CultureInfo.InvariantCulture);
            o.Minimo = int.Parse(Arg(a, "minimo", o.Minimo.ToString()), CultureInfo.InvariantCulture);
            o.Reintentos = int.Parse(Arg(a, "reintentos", o.Reintentos.ToString()), CultureInfo.InvariantCulture);
            o.EsperaMs = int.Parse(Arg(a, "espera-ms", o.EsperaMs.ToString()), CultureInfo.InvariantCulture);
            o.MaxErroresFisicos = int.Parse(Arg(a, "max-errores", o.MaxErroresFisicos.ToString()), CultureInfo.InvariantCulture);
            o.Rapido = Arg(a, "fase", "completa") == "rapida";
            o.VerificarOrigen = Arg(a, "verificar-origen", "si") != "no";
            o.Margen = long.Parse(Arg(a, "margen", o.Margen.ToString()), CultureInfo.InvariantCulture);
            string corte = Arg(a, "prueba-cortar-tras", null);
            if (corte != null)
            {
                if (Environment.GetEnvironmentVariable("TITAN_MODO_PRUEBA") != "1") throw new Rechazo("--prueba-cortar-tras solo en modo de prueba.");
                o.CortarTras = long.Parse(corte, CultureInfo.InvariantCulture);
            }
            if (o.Bloque < 512 || o.Minimo < 512 || o.Bloque % 512 != 0 || o.Minimo % 512 != 0) throw new ArgumentException("bloque y minimo deben ser múltiplos de 512");
            if (o.Reintentos < 0 || o.Reintentos > 20) throw new ArgumentException("reintentos entre 0 y 20");
            return o;
        }

        static string JsonResultado(ResultadoCopia r, string origen, string destino, string mapa)
        {
            return new Json().S("estado", r.Estado).S("categoria", r.Categoria).N("codigoWin32", r.CodigoWin32).S("mensaje", r.Mensaje)
                .S("origen", origen).S("destino", destino).S("mapa", mapa)
                .N("tamano", r.Tamano).N("bytesOk", r.BytesOk).N("bytesMalos", r.BytesMalos).N("bytesPendientes", r.BytesPendientes)
                .S("hashOrigen", r.HashOrigen).S("hashDestino", r.HashDestino)
                .N("lecturas", r.Lecturas).N("errores", r.Errores).B("fisico", r.Fisico).B("reanudado", r.Reanudado > 0)
                .S("estrategia", r.Estrategia).S("pasadas", r.Pasadas).B("interrumpido", r.Interrumpido).ToString();
        }

        // copiar / imagen comparten la lógica
        public static int Copiar(Dictionary<string, string> a, bool esImagen)
        {
            string origen = Arg(a, "origen", null), destino = Arg(a, "destino", null), rutaMapa = Arg(a, "mapa", null);
            if (origen == null || destino == null || rutaMapa == null) throw new ArgumentException("Faltan --origen, --destino o --mapa");
            if (Nat.EsDispositivo(destino) || Nat.EsDispositivo(rutaMapa)) throw new Rechazo("El destino y el mapa deben ser archivos, nunca dispositivos.");
            if (string.Equals(Normal(origen), Normal(destino), StringComparison.OrdinalIgnoreCase) || string.Equals(Normal(origen), Normal(rutaMapa), StringComparison.OrdinalIgnoreCase))
                throw new Rechazo("Origen y destino son el mismo archivo.");
            if (!esImagen && Nat.EsDispositivo(origen)) throw new ArgumentException("Para discos use el subcomando imagen.");
            Opciones op = LeerOpciones(a);
            ResultadoCopia r = new ResultadoCopia();
            IFuente src = null;
            int salida = 1;
            try
            {
                src = Fuentes.Abrir(origen, Arg(a, "prueba-fallos", null));
                r.Estrategia = src.Estrategia;
                long inicio = long.Parse(Arg(a, "inicio", "0"), CultureInfo.InvariantCulture);
                long longitud = long.Parse(Arg(a, "longitud", "-1"), CultureInfo.InvariantCulture);
                if (inicio > 0 || longitud >= 0)
                {
                    if (!esImagen) throw new ArgumentException("--inicio/--longitud solo para imagen");
                    src = new FuenteRango(src, inicio, longitud < 0 ? src.Longitud - inicio : longitud);
                }
                r.Tamano = src.Longitud;
                if (esImagen && src.Sector > op.Minimo) op.Minimo = src.Sector;

                Mapa mapa = null;
                bool hayMapa = Util.Existe(rutaMapa), hayDestino = Util.Existe(destino);
                if (hayMapa && hayDestino)
                {
                    try
                    {
                        mapa = Mapa.Cargar(rutaMapa, src.Longitud);
                        string o0;
                        if (mapa.Meta.TryGetValue("origen", out o0) && !string.Equals(o0, origen, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidDataException("El mapa pertenece a otro origen: " + o0);
                    }
                    catch (InvalidDataException ex)
                    {
                        Util.Progreso("mapa descartado: " + ex.Message);
                        mapa = null;
                    }
                }
                if (mapa == null) mapa = new Mapa(src.Longitud);
                mapa.Meta["origen"] = origen;
                mapa.Meta["tamano"] = src.Longitud.ToString(CultureInfo.InvariantCulture);

                // Espacio: lo que falta por reservar + margen
                long existente = 0;
                if (hayDestino)
                {
                    try { using (IFuente d0 = Fuentes.Abrir(destino, null)) existente = d0.Longitud; } catch { existente = 0; }
                }
                long necesario = Math.Max(0, src.Longitud - existente) + op.Margen;
                long libre = Util.EspacioLibre(Util.Dir(destino));
                if (libre < necesario)
                {
                    r.Estado = "PENDIENTE"; r.Categoria = Clasificador.SinEspacio; r.CodigoWin32 = 112;
                    r.Mensaje = "Espacio libre " + libre + " < necesario " + necesario;
                    r.BytesPendientes = src.Longitud;
                    Console.WriteLine("TITAN_RESULTADO " + JsonResultado(r, origen, destino, rutaMapa));
                    return 1;
                }

                using (Destino dst = new Destino(destino, src.Longitud))
                {
                    Motor m = new Motor(src, dst, mapa, rutaMapa, op);
                    try { m.Ejecutar(); }
                    catch (OperationCanceledException)
                    {
                        r = m.R; r.Estado = "PENDIENTE"; r.Categoria = "INTERRUMPIDO"; r.Tamano = src.Longitud;
                        r.BytesOk = mapa.Bytes('+'); r.BytesPendientes = src.Longitud - r.BytesOk;
                        r.Mensaje = "Interrumpido; se puede reanudar con el mismo mapa";
                        Console.WriteLine("TITAN_RESULTADO " + JsonResultado(r, origen, destino, rutaMapa));
                        return 3;
                    }
                    r = m.R; r.Estado = "?"; r.Tamano = src.Longitud;
                    r.BytesOk = mapa.Bytes('+'); r.BytesMalos = mapa.Bytes('-') + mapa.Bytes('*') + mapa.Bytes('/');
                    r.BytesPendientes = mapa.Bytes('?');
                    r.Estrategia = src.Estrategia + (op.Rapido ? "+rapida" : "+completa");
                    string hashSec = m.HashSecuencial();
                    dst.Vaciar();
                    dst.Dispose();
                    r.HashDestino = Util.Sha256Archivo(destino);
                    if (mapa.Completo)
                    {
                        if (hashSec != null) r.HashOrigen = hashSec;
                        else if (op.VerificarOrigen && !esImagen)
                        {
                            try { r.HashOrigen = Util.Sha256(src); }
                            catch (ErrorLectura) { r.HashOrigen = null; }
                        }
                        if (r.HashOrigen == null) { r.Estado = "RECUPERADO_SIN_VERIFICACION_COMPLETA"; r.Mensaje = "Copia completa; el origen no se pudo releer entero para comparar el SHA-256."; salida = 0; }
                        else if (r.HashOrigen == r.HashDestino) { r.Estado = "RECUPERADO_INTEGRO"; salida = 0; }
                        else { r.Estado = "ERROR_RECUPERACION"; r.Categoria = Clasificador.Integridad; r.Mensaje = "El SHA-256 de la copia no coincide con el del origen."; }
                    }
                    else if (r.BytesOk > 0)
                    {
                        r.Estado = "RECUPERADO_PARCIAL"; r.Categoria = r.Fisico ? Clasificador.Fisico : Clasificador.Parcial;
                        r.Mensaje = "Zonas ilegibles rellenadas con ceros; ver el mapa.";
                    }
                    else
                    {
                        r.Estado = "ERROR_RECUPERACION"; r.Categoria = Clasificador.Categoria(r.CodigoWin32);
                        if (src.Longitud == 0) { r.Estado = "RECUPERADO_INTEGRO"; r.HashOrigen = r.HashDestino; salida = 0; }
                    }
                }
            }
            catch (ErrorLectura e)
            {
                r.Estado = Clasificador.EsDesconexion(e.Codigo) ? "PENDIENTE" : "ERROR_RECUPERACION";
                r.Categoria = Clasificador.Categoria(e.Codigo); r.CodigoWin32 = e.Codigo; r.Mensaje = e.Message;
            }
            catch (ErrorEscritura e)
            {
                r.Estado = "PENDIENTE"; r.Categoria = Clasificador.Categoria(e.Codigo) == Clasificador.SinEspacio ? Clasificador.SinEspacio : "ERROR_DESTINO";
                r.CodigoWin32 = e.Codigo; r.Mensaje = e.Message;
            }
            finally { if (src != null) src.Dispose(); }
            Console.WriteLine("TITAN_RESULTADO " + JsonResultado(r, origen, destino, rutaMapa));
            return salida;
        }

        public static int Sha(Dictionary<string, string> a)
        {
            string ruta = Arg(a, "archivo", null);
            try
            {
                string h = Util.Sha256Archivo(ruta);
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("archivo", ruta).S("sha256", h).ToString());
                return 0;
            }
            catch (ErrorLectura e)
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "ERROR").S("archivo", ruta).S("categoria", Clasificador.Categoria(e.Codigo)).N("codigoWin32", e.Codigo).S("mensaje", e.Message).ToString());
                return 1;
            }
        }

        public static int Info(Dictionary<string, string> a)
        {
            string o = Arg(a, "origen", null);
            using (IFuente f = Fuentes.Abrir(o, null))
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("origen", o).N("longitud", f.Longitud).N("sector", f.Sector).ToString());
            }
            return 0;
        }

        // ---------------------------------------------------------------- VHD
        public static byte[] PieVhd(long tam, Guid id, DateTime cuando)
        {
            byte[] f = new byte[512];
            Encoding.ASCII.GetBytes("conectix").CopyTo(f, 0);
            Util.PonBE32(f, 8, 2);
            Util.PonBE32(f, 12, 0x00010000);
            Util.PonBE64(f, 16, 0xFFFFFFFFFFFFFFFFUL);
            Util.PonBE32(f, 24, (uint)(cuando - new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);
            Encoding.ASCII.GetBytes("tita").CopyTo(f, 28);
            Util.PonBE32(f, 32, 0x00010000);
            Util.PonBE32(f, 36, 0x5769326B); // "Wi2k"
            Util.PonBE64(f, 40, (ulong)tam);
            Util.PonBE64(f, 48, (ulong)tam);
            // Geometría CHS (algoritmo de la especificación VHD)
            long totalSect = tam / 512;
            if (totalSect > 65535L * 16 * 255) totalSect = 65535L * 16 * 255;
            long spt, cabezas, cilXcab;
            if (totalSect >= 65535L * 16 * 63) { spt = 255; cabezas = 16; cilXcab = totalSect / spt; }
            else
            {
                spt = 17; cilXcab = totalSect / spt;
                cabezas = (cilXcab + 1023) / 1024;
                if (cabezas < 4) cabezas = 4;
                if (cilXcab >= cabezas * 1024 || cabezas > 16) { spt = 31; cabezas = 16; cilXcab = totalSect / spt; }
                if (cilXcab >= cabezas * 1024) { spt = 63; cabezas = 16; cilXcab = totalSect / spt; }
            }
            long cil = cilXcab / cabezas;
            Util.PonBE16(f, 56, (ushort)Math.Min(cil, 65535));
            f[58] = (byte)cabezas; f[59] = (byte)spt;
            Util.PonBE32(f, 60, 2); // disco fijo
            id.ToByteArray().CopyTo(f, 68);
            uint suma = 0;
            for (int i = 0; i < 512; i++) suma += f[i];
            Util.PonBE32(f, 64, ~suma);
            return f;
        }

        public static int Vhd(Dictionary<string, string> a)
        {
            string img = Arg(a, "imagen", null), salida = Arg(a, "salida", null);
            if (img == null || salida == null) throw new ArgumentException("Faltan --imagen y --salida");
            if (Nat.EsDispositivo(img) || Nat.EsDispositivo(salida)) throw new Rechazo("vhd solo trabaja con archivos.");
            long tam;
            using (IFuente f = Fuentes.Abrir(img, null)) tam = f.Longitud;
            if (tam % 512 != 0) throw new ArgumentException("La imagen debe medir un múltiplo de 512 bytes.");
            // ¿ya tiene pie?
            byte[] cola = new byte[512];
            using (IFuente f = Fuentes.Abrir(img, null)) { if (tam >= 512) f.Leer(tam - 512, cola, 512); }
            if (Encoding.ASCII.GetString(cola, 0, 8) == "conectix") throw new Rechazo("La imagen ya tiene pie VHD.");
            byte[] pie = PieVhd(tam, Guid.NewGuid(), DateTime.UtcNow);
            using (Destino d = new Destino(img, tam + 512)) { d.Escribir(tam, pie, 512); d.Vaciar(); }
            Util.Mover(img, salida);
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("vhd", salida).N("datos", tam).ToString());
            return 0;
        }

        // ---------------------------------------------------------- Particiones
        static string Ascii(byte[] b, int o, int n) { return Encoding.ASCII.GetString(b, o, n); }

        static string DetectarFs(byte[] s, out long bytes)
        {
            bytes = 0;
            if (s[510] != 0x55 || s[511] != 0xAA) return null;
            if (Ascii(s, 3, 8) == "NTFS    ")
            {
                int bps = BitConverter.ToUInt16(s, 11);
                long sect = BitConverter.ToInt64(s, 40);
                if (bps != 512 && bps != 1024 && bps != 2048 && bps != 4096) return null;
                if (sect <= 0) return null;
                bytes = (sect + 1) * bps; // + sector de arranque de respaldo
                return "NTFS";
            }
            if (Ascii(s, 3, 8) == "EXFAT   ")
            {
                long sect = BitConverter.ToInt64(s, 72);
                int sh = s[108];
                if (sh < 9 || sh > 12) return null;
                bytes = sect << sh;
                return "exFAT";
            }
            if (Ascii(s, 82, 8) == "FAT32   ")
            {
                int bps = BitConverter.ToUInt16(s, 11);
                long sect = BitConverter.ToUInt32(s, 32);
                if (bps != 512 && bps != 4096) return null;
                bytes = sect * bps;
                return "FAT32";
            }
            return null;
        }

        public static int Particiones(Dictionary<string, string> a)
        {
            string o = Arg(a, "origen", null);
            long maxBytes = long.Parse(Arg(a, "max-bytes", "-1"), CultureInfo.InvariantCulture);
            List<string> tabla = new List<string>(), halladas = new List<string>();
            List<long> inicios = new List<long>();
            string estilo = "DESCONOCIDO";
            int errores = 0;
            using (IFuente f = Fuentes.Abrir(o, null))
            {
                int sec = 512;
                byte[] s0 = new byte[512];
                f.Leer(0, s0, 512);
                if (s0[510] == 0x55 && s0[511] == 0xAA)
                {
                    estilo = "MBR";
                    bool gpt = false;
                    for (int i = 0; i < 4; i++)
                    {
                        int e = 446 + i * 16;
                        byte tipo = s0[e + 4];
                        if (tipo == 0) continue;
                        if (tipo == 0xEE) { gpt = true; continue; }
                        long lba = BitConverter.ToUInt32(s0, e + 8), n = BitConverter.ToUInt32(s0, e + 12);
                        inicios.Add(lba * sec);
                        tabla.Add(new Json().S("estilo", "MBR").S("tipo", "0x" + tipo.ToString("X2")).N("inicioBytes", lba * sec).N("bytes", n * sec).ToString());
                    }
                    if (gpt)
                    {
                        estilo = "GPT";
                        byte[] h = new byte[512];
                        f.Leer(512, h, 512);
                        if (Ascii(h, 0, 8) == "EFI PART")
                        {
                            long lbaEnt = BitConverter.ToInt64(h, 72);
                            int nEnt = BitConverter.ToInt32(h, 80), tamEnt = BitConverter.ToInt32(h, 84);
                            if (nEnt > 0 && nEnt <= 1024 && tamEnt >= 128 && tamEnt <= 1024)
                            {
                                byte[] ents = new byte[nEnt * tamEnt];
                                f.Leer(lbaEnt * sec, ents, ents.Length);
                                for (int i = 0; i < nEnt; i++)
                                {
                                    int b = i * tamEnt;
                                    bool vacia = true;
                                    for (int k = 0; k < 16; k++) if (ents[b + k] != 0) { vacia = false; break; }
                                    if (vacia) continue;
                                    Guid tipo = new Guid(SubArray(ents, b, 16));
                                    long ini = BitConverter.ToInt64(ents, b + 32), fin = BitConverter.ToInt64(ents, b + 40);
                                    string nombre = Encoding.Unicode.GetString(ents, b + 56, 72).TrimEnd('\0');
                                    inicios.Add(ini * sec);
                                    tabla.Add(new Json().S("estilo", "GPT").S("tipo", tipo.ToString()).S("nombre", nombre).N("inicioBytes", ini * sec).N("bytes", (fin - ini + 1) * sec).ToString());
                                }
                            }
                        }
                        else estilo = "GPT_DANADO";
                    }
                }
                // Búsqueda de sectores de arranque en cada MiB (y en el sector 63, alineación antigua)
                long limite = maxBytes > 0 ? Math.Min(maxBytes, f.Longitud) : f.Longitud;
                if (a.ContainsKey("solo-tabla")) limite = 0; // solo leer la tabla y los inicios de partición
                List<long> posiciones = new List<long>();
                posiciones.Add(63L * 512);
                // Primeros 16 MiB: cada 4 KiB (particiones con alineación antigua o de 64 KiB)
                for (long p = 0; p < Math.Min(limite, 16L << 20); p += 4096) posiciones.Add(p);
                for (long p = 16L << 20; p < limite; p += 1L << 20) posiciones.Add(p);
                foreach (long ini in inicios) posiciones.Add(ini);
                posiciones.Sort();
                for (int i = posiciones.Count - 1; i > 0; i--) if (posiciones[i] == posiciones[i - 1]) posiciones.RemoveAt(i);
                byte[] s = new byte[512];
                long ultimoFin = -1;
                int cuenta = 0;
                foreach (long p in posiciones)
                {
                    if (p + 512 > f.Longitud) continue;
                    if (p < ultimoFin) continue; // dentro de un volumen ya hallado
                    cuenta++;
                    if (cuenta % 4096 == 0) Util.Progreso("particiones " + p + " " + limite);
                    try { f.Leer(p, s, 512); }
                    catch (ErrorLectura) { errores++; continue; }
                    long bytes;
                    string fs = DetectarFs(s, out bytes);
                    if (fs == null) continue;
                    bool enTabla = inicios.Contains(p);
                    halladas.Add(new Json().S("fs", fs).N("inicioBytes", p).N("bytes", bytes).B("enTabla", enTabla).ToString());
                    ultimoFin = p + Math.Max(bytes, 512);
                }
            }
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("origen", o).S("estilo", estilo).Crudo("tabla", Json.Lista(tabla)).Crudo("halladas", Json.Lista(halladas)).N("erroresLectura", errores).ToString());
            return 0;
        }

        static byte[] SubArray(byte[] b, int o, int n) { byte[] r = new byte[n]; Buffer.BlockCopy(b, o, r, 0, n); return r; }

        public static int ReconstruirMbr(Dictionary<string, string> a)
        {
            string img = Arg(a, "imagen", null);
            string particiones = Arg(a, "particiones", null); // "inicioBytes:bytes:tipoHex,..."
            if (img == null || particiones == null) throw new ArgumentException("Faltan --imagen y --particiones");
            if (Nat.EsDispositivo(img)) throw new Rechazo("La reconstrucción solo se hace sobre una COPIA de imagen, nunca sobre un disco.");
            string lower = img.ToLowerInvariant();
            if (!(lower.EndsWith(".img") || lower.EndsWith(".vhd"))) throw new Rechazo("Solo se aceptan imágenes .img o .vhd.");
            long tam;
            byte[] s0 = new byte[512];
            using (IFuente f = Fuentes.Abrir(img, null)) { tam = f.Longitud; f.Leer(0, s0, 512); }
            string bak = img + ".sector0.bak";
            if (!Util.Existe(bak))
            {
                using (Destino d = new Destino(bak, 512)) { d.Escribir(0, s0, 512); d.Vaciar(); }
            }
            byte[] mbr = new byte[512];
            Buffer.BlockCopy(s0, 0, mbr, 0, 440);
            byte[] firma = Guid.NewGuid().ToByteArray();
            Buffer.BlockCopy(firma, 0, mbr, 440, 4);
            string[] partes = particiones.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
            if (partes.Length > 4) throw new ArgumentException("Máximo 4 particiones en un MBR");
            for (int i = 0; i < partes.Length; i++)
            {
                string[] p = partes[i].Split(':');
                long ini = long.Parse(p[0], CultureInfo.InvariantCulture), bytes = long.Parse(p[1], CultureInfo.InvariantCulture);
                byte tipo = byte.Parse(p[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                if (ini % 512 != 0 || ini <= 0) throw new ArgumentException("Inicio no alineado a 512");
                long lba = ini / 512, n = bytes / 512;
                if (lba + n > tam / 512 + 1) n = tam / 512 - lba;
                if (lba > uint.MaxValue || n > uint.MaxValue) throw new ArgumentException("Más de 2 TiB: no cabe en un MBR");
                int e = 446 + i * 16;
                mbr[e] = 0; mbr[e + 1] = 0xFE; mbr[e + 2] = 0xFF; mbr[e + 3] = 0xFF;
                mbr[e + 4] = tipo; mbr[e + 5] = 0xFE; mbr[e + 6] = 0xFF; mbr[e + 7] = 0xFF;
                BitConverter.GetBytes((uint)lba).CopyTo(mbr, e + 8);
                BitConverter.GetBytes((uint)n).CopyTo(mbr, e + 12);
            }
            mbr[510] = 0x55; mbr[511] = 0xAA;
            using (Destino d = new Destino(img, tam)) { d.Escribir(0, mbr, 512); d.Vaciar(); }
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("imagen", img).S("copiaSector0", bak).N("particiones", partes.Length).ToString());
            return 0;
        }

        // CRC32 (IEEE) para cabeceras GPT
        static uint[] tablaCrc;
        public static uint Crc32(byte[] b, int o, int n)
        {
            if (tablaCrc == null)
            {
                tablaCrc = new uint[256];
                for (uint i = 0; i < 256; i++)
                {
                    uint c = i;
                    for (int k = 0; k < 8; k++) c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
                    tablaCrc[i] = c;
                }
            }
            uint crc = 0xFFFFFFFF;
            for (int i = o; i < o + n; i++) crc = tablaCrc[(crc ^ b[i]) & 0xFF] ^ (crc >> 8);
            return ~crc;
        }

        static bool CambiarGuidCabeceraGpt(byte[] h, Guid nuevo)
        {
            if (Ascii(h, 0, 8) != "EFI PART") return false;
            int tam = BitConverter.ToInt32(h, 12);
            if (tam < 92 || tam > 512) return false;
            nuevo.ToByteArray().CopyTo(h, 56);
            BitConverter.GetBytes(0u).CopyTo(h, 16);
            BitConverter.GetBytes(Crc32(h, 0, tam)).CopyTo(h, 16);
            return true;
        }

        // Da a una COPIA de imagen una identidad de disco nueva (firma MBR y GUID de
        // disco GPT) para montarla junto al disco original sin "colisión de firma".
        public static int NuevaFirma(Dictionary<string, string> a)
        {
            string img = Arg(a, "imagen", null);
            if (img == null) throw new ArgumentException("Falta --imagen");
            if (Nat.EsDispositivo(img)) throw new Rechazo("Solo se modifica una COPIA de imagen, nunca un disco.");
            string lower = img.ToLowerInvariant();
            if (!(lower.EndsWith(".img") || lower.EndsWith(".vhd"))) throw new Rechazo("Solo se aceptan imágenes .img o .vhd.");
            long tam;
            byte[] s0 = new byte[512], s1 = new byte[512];
            using (IFuente f = Fuentes.Abrir(img, null)) { tam = f.Longitud; f.Leer(0, s0, 512); f.Leer(512, s1, 512); }
            bool vhd = false;
            byte[] cola = new byte[512];
            using (IFuente f = Fuentes.Abrir(img, null)) { f.Leer(tam - 512, cola, 512); }
            if (Ascii(cola, 0, 8) == "conectix") { vhd = true; tam -= 512; }
            string bak = img + ".firma.bak";
            List<string> cambios = new List<string>();
            using (Destino d = new Destino(img, vhd ? tam + 512 : tam))
            {
                if (!Util.Existe(bak)) { using (Destino b = new Destino(bak, 1024)) { b.Escribir(0, s0, 512); b.Escribir(512, s1, 512); b.Vaciar(); } }
                if (s0[510] == 0x55 && s0[511] == 0xAA)
                {
                    bool gpt = false;
                    for (int i = 0; i < 4; i++) if (s0[446 + i * 16 + 4] == 0xEE) gpt = true;
                    if (!gpt)
                    {
                        byte[] sig = Guid.NewGuid().ToByteArray();
                        Buffer.BlockCopy(sig, 0, s0, 440, 4);
                        d.Escribir(0, s0, 512);
                        cambios.Add("MBR " + BitConverter.ToUInt32(s0, 440).ToString("X8"));
                    }
                    else
                    {
                        Guid g = Guid.NewGuid();
                        if (CambiarGuidCabeceraGpt(s1, g))
                        {
                            d.Escribir(512, s1, 512);
                            cambios.Add("GPT principal " + g);
                            long lbaRespaldo = BitConverter.ToInt64(s1, 32);
                            if (lbaRespaldo > 1 && (lbaRespaldo + 1) * 512 <= tam)
                            {
                                byte[] r = new byte[512];
                                using (IFuente f = Fuentes.Abrir(img, null)) f.Leer(lbaRespaldo * 512, r, 512);
                                if (CambiarGuidCabeceraGpt(r, g)) { d.Escribir(lbaRespaldo * 512, r, 512); cambios.Add("GPT respaldo"); }
                            }
                        }
                    }
                }
                d.Vaciar();
            }
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", cambios.Count > 0 ? "OK" : "SIN_CAMBIOS").S("imagen", img).S("cambios", string.Join("; ", cambios.ToArray())).S("copia", bak).ToString());
            return 0;
        }

        // Identifica el contenido de un volumen por su sector de arranque (solo lectura)
        public static int Volumen(Dictionary<string, string> a)
        {
            string o = Arg(a, "origen", null);
            if (o == null) throw new ArgumentException("Falta --origen");
            byte[] s = new byte[512];
            long lon;
            using (IFuente f = Fuentes.Abrir(o, null)) { lon = f.Longitud; f.Leer(0, s, 512); }
            string oem = Encoding.ASCII.GetString(s, 3, 8);
            long bytes;
            string fs = DetectarFs(s, out bytes);
            bool bitlocker = oem == "-FVE-FS-";
            bool vacio = true;
            for (int i = 0; i < 512; i++) if (s[i] != 0) { vacio = false; break; }
            string tipo = bitlocker ? "BITLOCKER" : (fs ?? (vacio ? "VACIO" : "DESCONOCIDO"));
            StringBuilder limpio = new StringBuilder();
            foreach (char c in oem) limpio.Append(c >= 32 && c < 127 ? c : '.');
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("origen", o).S("tipo", tipo).S("oem", limpio.ToString()).B("bitlocker", bitlocker).N("longitud", lon).ToString());
            return 0;
        }

        public static int Salud(Dictionary<string, string> a)
        {
            if (!Nat.EsWindows) throw new Rechazo("salud solo funciona en Windows.");
            int disco = int.Parse(Arg(a, "disco", "-1"), CultureInfo.InvariantCulture);
            if (disco < 0) throw new ArgumentException("Falta --disco N");
            Console.WriteLine("TITAN_RESULTADO " + SaludDisco.Consultar(disco));
            return 0;
        }
    }

    // Rango de una fuente (para imágenes de una partición)
    class FuenteRango : IFuente
    {
        IFuente f; long ini, lon;
        public FuenteRango(IFuente fuente, long inicio, long longitud)
        {
            f = fuente; ini = inicio; lon = longitud;
            if (inicio < 0 || longitud < 0 || inicio + longitud > fuente.Longitud) throw new ArgumentException("Rango fuera del origen");
        }
        public long Longitud { get { return lon; } }
        public int Sector { get { return f.Sector; } }
        public string Estrategia { get { return f.Estrategia; } }
        public int Leer(long pos, byte[] buf, int n)
        {
            if (pos + n > lon) n = (int)(lon - pos);
            return f.Leer(ini + pos, buf, n);
        }
        public void Dispose() { f.Dispose(); }
    }

    // -------------------------------------------------------------------------
    // Salud del disco: NVMe (registro SMART/Health 02h) o predicción de fallo
    // -------------------------------------------------------------------------
    static class SaludDisco
    {
        const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
        const uint IOCTL_STORAGE_PREDICT_FAILURE = 0x002D1100;

        static string LeerCadena(byte[] b, int off)
        {
            if (off <= 0 || off >= b.Length) return "";
            int fin = off;
            while (fin < b.Length && b[fin] != 0) fin++;
            return Encoding.ASCII.GetString(b, off, fin - off).Trim();
        }

        static decimal U128(byte[] b, int o)
        {
            // Solo los 8 bytes bajos (suficiente para valores reales)
            return (decimal)BitConverter.ToUInt64(b, o);
        }

        public static string Consultar(int disco)
        {
            Json j = new Json().S("estado", "OK").N("disco", disco);
            // Abrir SIN permiso de escritura: solo consultas
            SafeFileHandle h = Nat.CreateFileW(@"\\.\PhysicalDrive" + disco, 0, Nat.FILE_SHARE_READ | Nat.FILE_SHARE_WRITE, IntPtr.Zero, Nat.OPEN_EXISTING, 0, IntPtr.Zero);
            if (h.IsInvalid) return new Json().S("estado", "ERROR").N("disco", disco).N("codigoWin32", Marshal.GetLastWin32Error()).S("mensaje", "No se pudo abrir el disco").ToString();
            using (h)
            {
                int dev;
                // StorageDeviceProperty (0), PropertyStandardQuery (0)
                byte[] q = new byte[12];
                byte[] d = new byte[1024];
                string bus = "Desconocido";
                if (Nat.DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, q, q.Length, d, d.Length, out dev, IntPtr.Zero))
                {
                    int busType = BitConverter.ToInt32(d, 28);
                    string[] buses = { "Desconocido", "SCSI", "ATAPI", "ATA", "1394", "SSA", "FibreChannel", "USB", "RAID", "iSCSI", "SAS", "SATA", "SD", "MMC", "Virtual", "FileBackedVirtual", "Spaces", "NVMe", "SCM", "UFS" };
                    bus = busType >= 0 && busType < buses.Length ? buses[busType] : busType.ToString();
                    j.S("bus", bus).S("fabricante", LeerCadena(d, BitConverter.ToInt32(d, 12))).S("modelo", LeerCadena(d, BitConverter.ToInt32(d, 16))).S("serie", LeerCadena(d, BitConverter.ToInt32(d, 24)));
                }
                if (bus == "NVMe")
                {
                    // STORAGE_PROPERTY_QUERY (8) + STORAGE_PROTOCOL_SPECIFIC_DATA (40) + 512 de datos
                    byte[] e = new byte[8 + 40 + 512];
                    BitConverter.GetBytes(50).CopyTo(e, 0);  // StorageDeviceProtocolSpecificProperty
                    BitConverter.GetBytes(0).CopyTo(e, 4);   // PropertyStandardQuery
                    BitConverter.GetBytes(3).CopyTo(e, 8);   // ProtocolTypeNvme
                    BitConverter.GetBytes(2).CopyTo(e, 12);  // NVMeDataTypeLogPage
                    BitConverter.GetBytes(2).CopyTo(e, 16);  // Log 02h: SMART / Health
                    BitConverter.GetBytes(0).CopyTo(e, 20);
                    BitConverter.GetBytes(40).CopyTo(e, 24); // ProtocolDataOffset
                    BitConverter.GetBytes(512).CopyTo(e, 28);
                    byte[] s = new byte[e.Length];
                    if (Nat.DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, e, e.Length, s, s.Length, out dev, IntPtr.Zero))
                    {
                        int off = 8 + BitConverter.ToInt32(s, 8 + 16); // descriptor(8) + ProtocolDataOffset
                        if (off + 192 <= s.Length)
                        {
                            byte aviso = s[off];
                            int tempK = BitConverter.ToUInt16(s, off + 1);
                            j.N("nvmeAvisoCritico", aviso)
                             .N("temperaturaC", tempK > 0 ? tempK - 273 : 0)
                             .N("reservaDisponiblePct", s[off + 3]).N("reservaUmbralPct", s[off + 4])
                             .N("desgastePct", s[off + 5])
                             .N("horasEncendido", (long)U128(s, off + 128))
                             .N("apagadosInseguros", (long)U128(s, off + 144))
                             .N("erroresIntegridadMedio", (long)U128(s, off + 160))
                             .N("entradasRegistroErrores", (long)U128(s, off + 176));
                            string veredicto = "BUENO";
                            if ((aviso & 0x1F) != 0 || U128(s, off + 160) > 0) veredicto = "MALO";
                            else if (s[off + 5] >= 90 || s[off + 3] <= s[off + 4]) veredicto = "DUDOSO";
                            j.S("veredicto", veredicto).S("fuente", "NVMe registro 02h");
                            return j.ToString();
                        }
                    }
                    j.N("nvmeCodigoWin32", Marshal.GetLastWin32Error());
                }
                byte[] pf = new byte[516];
                if (Nat.DeviceIoControl(h, IOCTL_STORAGE_PREDICT_FAILURE, null, 0, pf, pf.Length, out dev, IntPtr.Zero))
                {
                    int predice = BitConverter.ToInt32(pf, 0);
                    j.B("prediceFallo", predice != 0).S("veredicto", predice != 0 ? "MALO" : "BUENO").S("fuente", "IOCTL_STORAGE_PREDICT_FAILURE");
                }
                else j.S("veredicto", "DESCONOCIDO").N("prediccionCodigoWin32", Marshal.GetLastWin32Error()).S("fuente", "ninguna");
            }
            return j.ToString();
        }
    }

    // -------------------------------------------------------------------------
    // Recuperación por firmas (carving). Solo lee el origen.
    // -------------------------------------------------------------------------
    class Tallador
    {
        IFuente f;
        long limite;
        long maxTam;
        // Caché de lectura para los analizadores
        byte[] cache = new byte[1 << 20]; long cacheIni = -1; int cacheLen;
        public int ErroresLectura;

        public Tallador(IFuente fuente, long lim, long max) { f = fuente; limite = lim; maxTam = max; }

        int B(long p)
        {
            if (p < 0 || p >= limite) return -1;
            if (cacheIni < 0 || p < cacheIni || p >= cacheIni + cacheLen)
            {
                long ini = p - (p % 512);
                int n = (int)Math.Min(cache.Length, limite - ini);
                try { cacheLen = f.Leer(ini, cache, n); }
                catch (ErrorLectura) { ErroresLectura++; cacheLen = 0; cacheIni = -1; return -1; }
                cacheIni = ini;
                if (p >= cacheIni + cacheLen) return -1;
            }
            return cache[p - cacheIni];
        }

        int U16be(long p) { int a = B(p), b = B(p + 1); if (a < 0 || b < 0) return -1; return a << 8 | b; }
        long U32be(long p) { int a = B(p), b = B(p + 1), c = B(p + 2), d = B(p + 3); if ((a | b | c | d) < 0) return -1; return ((long)a << 24) | ((long)b << 16) | ((long)c << 8) | (long)d; }
        long U32le(long p) { int a = B(p), b = B(p + 1), c = B(p + 2), d = B(p + 3); if ((a | b | c | d) < 0) return -1; return ((long)d << 24) | ((long)c << 16) | ((long)b << 8) | (long)a; }
        int U16le(long p) { int a = B(p), b = B(p + 1); if (a < 0 || b < 0) return -1; return b << 8 | a; }
        bool Igual(long p, string s) { for (int i = 0; i < s.Length; i++) if (B(p + i) != (byte)s[i]) return false; return true; }

        // Devuelve la longitud del archivo que empieza en p, o -1. tipo/ext de salida.
        public long Detectar(long p, byte[] cab, int off, out string ext, out bool completo)
        {
            ext = null; completo = false;
            if (cab[off] == 0xFF && cab[off + 1] == 0xD8 && cab[off + 2] == 0xFF && (cab[off + 3] >= 0xDB)) { ext = "jpg"; return Jpeg(p, out completo); }
            if (cab[off] == 0x89 && cab[off + 1] == 0x50 && cab[off + 2] == 0x4E && cab[off + 3] == 0x47 && cab[off + 4] == 0x0D && cab[off + 5] == 0x0A && cab[off + 6] == 0x1A && cab[off + 7] == 0x0A) { ext = "png"; return Png(p, out completo); }
            if (cab[off] == 'G' && cab[off + 1] == 'I' && cab[off + 2] == 'F' && cab[off + 3] == '8' && (cab[off + 4] == '7' || cab[off + 4] == '9') && cab[off + 5] == 'a') { ext = "gif"; return Gif(p, out completo); }
            if (cab[off] == '%' && cab[off + 1] == 'P' && cab[off + 2] == 'D' && cab[off + 3] == 'F' && cab[off + 4] == '-') { ext = "pdf"; return Pdf(p, out completo); }
            if (cab[off] == 'P' && cab[off + 1] == 'K' && cab[off + 2] == 3 && cab[off + 3] == 4) { return Zip(p, out ext, out completo); }
            if (Encoding.ASCII.GetString(cab, off, 16) == "SQLite format 3\0") { ext = "sqlite"; return Sqlite(p, out completo); }
            if (cab[off + 4] == 'f' && cab[off + 5] == 't' && cab[off + 6] == 'y' && cab[off + 7] == 'p') { return Mp4(p, out ext, out completo); }
            return -1;
        }

        long Jpeg(long p, out bool completo)
        {
            completo = false;
            long q = p + 2;
            while (q - p < maxTam)
            {
                if (B(q) != 0xFF) return -1;
                int m = B(q + 1);
                while (m == 0xFF) { q++; m = B(q + 1); }
                if (m < 0) return -1;
                if (m == 0xD9) { completo = true; return q + 2 - p; }
                if ((m >= 0xD0 && m <= 0xD7) || m == 0x01) { q += 2; continue; }
                int len = U16be(q + 2);
                if (len < 2) return -1;
                q += 2 + len;
                if (m == 0xDA)
                {
                    // Datos entrópicos hasta el siguiente marcador real
                    while (q - p < maxTam)
                    {
                        int b = B(q);
                        if (b < 0) return -1;
                        if (b == 0xFF)
                        {
                            int n = B(q + 1);
                            if (n == 0x00 || (n >= 0xD0 && n <= 0xD7) || n == 0xFF) { q += (n == 0xFF ? 1 : 2); continue; }
                            break;
                        }
                        q++;
                    }
                }
            }
            return -1;
        }

        long Png(long p, out bool completo)
        {
            completo = false;
            long q = p + 8;
            while (q - p < maxTam)
            {
                long len = U32be(q);
                if (len < 0 || len > 0x7FFFFFFF) return -1;
                for (int i = 4; i < 8; i++) { int c = B(q + i); if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return -1; }
                bool fin = Igual(q + 4, "IEND");
                q += 12 + len;
                if (fin) { completo = true; return q - p; }
            }
            return -1;
        }

        long SubBloques(long q)
        {
            while (true)
            {
                int n = B(q);
                if (n < 0) return -1;
                q++;
                if (n == 0) return q;
                q += n;
            }
        }

        long Gif(long p, out bool completo)
        {
            completo = false;
            long q = p + 6;
            int flags = B(q + 4);
            if (flags < 0) return -1;
            q += 7;
            if ((flags & 0x80) != 0) q += 3L * (1 << ((flags & 7) + 1));
            while (q - p < maxTam)
            {
                int b = B(q);
                if (b == 0x3B) { completo = true; return q + 1 - p; }
                if (b == 0x21) { q = SubBloques(q + 2); if (q < 0) return -1; continue; }
                if (b == 0x2C)
                {
                    int lf = B(q + 9);
                    if (lf < 0) return -1;
                    q += 10;
                    if ((lf & 0x80) != 0) q += 3L * (1 << ((lf & 7) + 1));
                    q += 1; // tamaño mínimo LZW
                    q = SubBloques(q);
                    if (q < 0) return -1;
                    continue;
                }
                return -1;
            }
            return -1;
        }

        long Pdf(long p, out bool completo)
        {
            completo = false;
            long ultimo = -1;
            for (long q = p + 5; q - p < maxTam; q++)
            {
                int b = B(q);
                if (b < 0) break;
                if (b == '%' && Igual(q, "%%EOF"))
                {
                    long fin = q + 5;
                    if (B(fin) == '\r') fin++;
                    if (B(fin) == '\n') fin++;
                    ultimo = fin;
                    q = fin - 1;
                    continue;
                }
                if (ultimo > 0 && q - ultimo > (1 << 20)) break;              // 1 MiB sin otro %%EOF
                if (q % 512 == 0 && Igual(q, "%PDF-") && q > p) break;        // otro PDF empieza aquí
            }
            if (ultimo > 0) { completo = true; return ultimo - p; }
            return -1;
        }

        long Zip(long p, out string ext, out bool completo)
        {
            ext = "zip"; completo = false;
            int nlen = U16le(p + 26);
            int elen = U16le(p + 28);
            string primero = "";
            if (nlen > 0 && nlen < 512)
            {
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < nlen; i++) sb.Append((char)B(p + 30 + i));
                primero = sb.ToString();
            }
            for (long q = p + 30; q - p < maxTam; q++)
            {
                int b = B(q);
                if (b < 0) return -1;
                if (b != 'P' || B(q + 1) != 'K' || B(q + 2) != 5 || B(q + 3) != 6) continue;
                long tamCd = U32le(q + 12), offCd = U32le(q + 16);
                int com = U16le(q + 20);
                if (tamCd < 0 || offCd < 0 || com < 0) continue;
                if (offCd + tamCd != q - p) continue; // EOCD de otro zip
                long fin = q + 22 + com;
                completo = true;
                // Tipo por el contenido del directorio central
                string cd = LeerAscii(p + offCd, (int)Math.Min(tamCd, 1 << 20));
                if (primero == "mimetype")
                {
                    string mt = LeerAscii(p + 30 + nlen + elen, 64);
                    if (mt.StartsWith("application/vnd.oasis.opendocument.text")) ext = "odt";
                    else if (mt.StartsWith("application/vnd.oasis.opendocument.spreadsheet")) ext = "ods";
                    else if (mt.StartsWith("application/vnd.oasis.opendocument.presentation")) ext = "odp";
                    else if (mt.StartsWith("application/epub+zip")) ext = "epub";
                }
                else if (cd.Contains("[Content_Types].xml"))
                {
                    if (cd.Contains("word/")) ext = "docx";
                    else if (cd.Contains("xl/")) ext = "xlsx";
                    else if (cd.Contains("ppt/")) ext = "pptx";
                }
                return fin - p;
            }
            return -1;
        }

        string LeerAscii(long p, int n)
        {
            StringBuilder sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) { int b = B(p + i); if (b < 0) break; sb.Append((char)b); }
            return sb.ToString();
        }

        long Sqlite(long p, out bool completo)
        {
            completo = false;
            int ps = U16be(p + 16);
            if (ps == 1) ps = 65536;
            if (ps < 512 || (ps & (ps - 1)) != 0) return -1;
            long paginas = U32be(p + 28);
            long cambio = U32be(p + 24), valido = U32be(p + 92);
            if (paginas <= 0 || cambio != valido) return -1; // tamaño en cabecera no fiable
            long tam = paginas * ps;
            if (tam > maxTam) return -1;
            completo = true;
            return tam;
        }

        long Mp4(long p, out string ext, out bool completo)
        {
            ext = "mp4"; completo = false;
            string marca = LeerAscii(p + 8, 4);
            if (marca == "qt  ") ext = "mov";
            else if (marca.StartsWith("3g")) ext = "3gp";
            else if (marca.StartsWith("M4A")) ext = "m4a";
            string[] conocidas = { "ftyp", "moov", "mdat", "free", "skip", "wide", "uuid", "pdin", "moof", "mfra", "meta", "sidx", "styp", "emsg", "prft", "udta", "pnot" };
            long q = p;
            bool moov = false, mdat = false;
            while (q - p < maxTam)
            {
                long tam = U32be(q);
                string tipo = LeerAscii(q + 4, 4);
                if (tam < 0 || Array.IndexOf(conocidas, tipo) < 0) break;
                if (tam == 1)
                {
                    long alto = U32be(q + 8), bajo = U32be(q + 12);
                    if (alto < 0 || bajo < 0) break;
                    tam = (alto << 32) | bajo;
                }
                if (tam < 8) break;
                if (tipo == "moov") moov = true;
                if (tipo == "mdat") mdat = true;
                q += tam;
            }
            if (q == p) return -1;
            completo = moov && mdat;
            return q - p;
        }
    }

    static class Firmas
    {
        public static int Ejecutar(Dictionary<string, string> a)
        {
            string o = a.ContainsKey("origen") ? a["origen"] : null;
            string destino = a.ContainsKey("destino") ? a["destino"] : null;
            if (o == null || destino == null) throw new ArgumentException("Faltan --origen y --destino");
            if (Nat.EsDispositivo(destino)) throw new Rechazo("El destino debe ser una carpeta.");
            long inicio = a.ContainsKey("inicio") ? long.Parse(a["inicio"], CultureInfo.InvariantCulture) : 0;
            long longitud = a.ContainsKey("longitud") ? long.Parse(a["longitud"], CultureInfo.InvariantCulture) : -1;
            long maxTam = (a.ContainsKey("max-mb") ? long.Parse(a["max-mb"], CultureInfo.InvariantCulture) : 512) << 20;
            int maxArchivos = a.ContainsKey("max-archivos") ? int.Parse(a["max-archivos"], CultureInfo.InvariantCulture) : 100000;
            string[] tipos = (a.ContainsKey("tipos") ? a["tipos"] : "jpg,png,gif,pdf,zip,sqlite,mp4").Split(',');
            Util.CrearCarpeta(destino);
            List<string> lista = new List<string>();
            int errores = 0;
            long escaneado = 0;
            using (IFuente f0 = Fuentes.Abrir(o, null))
            {
                IFuente f = (inicio > 0 || longitud >= 0) ? (IFuente)new FuenteRango(f0, inicio, longitud < 0 ? f0.Longitud - inicio : longitud) : f0;
                long lim = f.Longitud;
                Tallador t = new Tallador(f, lim, maxTam);
                byte[] buf = new byte[8 << 20];
                long pos = 0;
                DateTime ultimo = DateTime.UtcNow;
                while (pos < lim && lista.Count < maxArchivos)
                {
                    int n = (int)Math.Min(buf.Length, lim - pos);
                    int r;
                    try { r = f.Leer(pos, buf, n); }
                    catch (ErrorLectura)
                    {
                        errores++;
                        pos += 1 << 20; // saltar 1 MiB ilegible
                        continue;
                    }
                    if (r <= 0) break;
                    long saltarHasta = -1;
                    for (int off = 0; off + 16 <= r; off += 512)
                    {
                        long abs = pos + off;
                        string ext; bool completo;
                        long tam = t.Detectar(abs, buf, off, out ext, out completo);
                        if (tam <= 0 || ext == null || Array.IndexOf(tipos, TipoBase(ext)) < 0) continue;
                        string sub = Path.Combine(destino, TipoBase(ext));
                        string nombre = Path.Combine(sub, "f" + (inicio + abs).ToString("D14") + "." + ext);
                        string hash = Extraer(f, abs, tam, nombre);
                        if (hash == null) { errores++; continue; }
                        lista.Add(new Json().S("archivo", nombre).S("tipo", ext).N("offset", inicio + abs).N("tamano", tam).B("estructuraCompleta", completo).S("sha256", hash).ToString());
                        long fin = abs + tam;
                        long finAlineado = (fin + 511) / 512 * 512;
                        if (finAlineado > pos + off + 512) { saltarHasta = finAlineado; break; }
                        if (lista.Count >= maxArchivos) break;
                    }
                    escaneado = pos + r;
                    if ((DateTime.UtcNow - ultimo).TotalSeconds >= 2) { Util.Progreso("firmas " + escaneado + " " + lim + " hallados " + lista.Count); ultimo = DateTime.UtcNow; }
                    if (saltarHasta > 0) pos = saltarHasta; else pos += r;
                }
                errores += t.ErroresLectura;
                if (!object.ReferenceEquals(f, f0)) { }
            }
            // índice en disco
            string indice = Path.Combine(destino, "indice_firmas.json");
            Util.EscribirTexto(indice, Json.Lista(lista));
            Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("origen", o).S("destino", destino).N("hallados", lista.Count).N("erroresLectura", errores).N("bytesEscaneados", escaneado).S("indice", indice).ToString());
            return 0;
        }

        static string TipoBase(string ext)
        {
            switch (ext)
            {
                case "docx": case "xlsx": case "pptx": case "odt": case "ods": case "odp": case "epub": return "zip";
                case "mov": case "3gp": case "m4a": return "mp4";
                default: return ext;
            }
        }

        static string Extraer(IFuente f, long pos, long tam, string nombre)
        {
            try
            {
                using (SHA256 sha = SHA256.Create())
                using (Destino d = new Destino(nombre, tam))
                {
                    byte[] buf = new byte[1 << 20];
                    long hecho = 0;
                    while (hecho < tam)
                    {
                        int n = (int)Math.Min(buf.Length, tam - hecho);
                        int r = f.Leer(pos + hecho, buf, n);
                        if (r <= 0) return null;
                        d.Escribir(hecho, buf, r);
                        sha.TransformBlock(buf, 0, r, null, 0);
                        hecho += r;
                    }
                    sha.TransformFinalBlock(buf, 0, 0);
                    d.Vaciar();
                    return Util.Hex(sha.Hash);
                }
            }
            catch (ErrorLectura) { return null; }
        }
    }

    // -------------------------------------------------------------------------
    // Programa
    // -------------------------------------------------------------------------
    static class Programa
    {
        static Dictionary<string, string> Args(string[] args, int desde)
        {
            Dictionary<string, string> d = new Dictionary<string, string>();
            for (int i = desde; i < args.Length; i++)
            {
                if (!args[i].StartsWith("--")) throw new ArgumentException("Argumento no válido: " + args[i]);
                string k = args[i].Substring(2);
                string v = (i + 1 < args.Length && !args[i + 1].StartsWith("--")) ? args[++i] : "si";
                d[k] = v;
            }
            return d;
        }

        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("TitanRescate 1.0 - subcomandos: copiar, imagen, vhd, particiones, reconstruir-mbr, firmas, salud, info, sha256, version");
                return 2;
            }
            try
            {
                Dictionary<string, string> a = Args(args, 1);
                switch (args[0])
                {
                    case "version": Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "OK").S("version", "1.0").S("plataforma", Environment.OSVersion.ToString()).B("x64", IntPtr.Size == 8).S("clr", Environment.Version.ToString()).ToString()); return 0;
                    case "copiar": return Comandos.Copiar(a, false);
                    case "imagen": return Comandos.Copiar(a, true);
                    case "vhd": return Comandos.Vhd(a);
                    case "particiones": return Comandos.Particiones(a);
                    case "reconstruir-mbr": return Comandos.ReconstruirMbr(a);
                    case "nueva-firma": return Comandos.NuevaFirma(a);
                    case "volumen": return Comandos.Volumen(a);
                    case "firmas": return Firmas.Ejecutar(a);
                    case "salud": return Comandos.Salud(a);
                    case "info": return Comandos.Info(a);
                    case "sha256": return Comandos.Sha(a);
                    default: throw new ArgumentException("Subcomando desconocido: " + args[0]);
                }
            }
            catch (Rechazo e)
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "RECHAZADO").S("mensaje", e.Message).ToString());
                return 4;
            }
            catch (ArgumentException e)
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "ARGUMENTOS").S("mensaje", e.Message).ToString());
                return 2;
            }
            catch (ErrorLectura e)
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "ERROR").S("categoria", Clasificador.Categoria(e.Codigo)).N("codigoWin32", e.Codigo).S("mensaje", e.Message).ToString());
                return 1;
            }
            catch (Exception e)
            {
                Console.WriteLine("TITAN_RESULTADO " + new Json().S("estado", "ERROR").S("categoria", "OTRO").S("mensaje", e.GetType().Name + ": " + e.Message).ToString());
                return 1;
            }
        }
    }
}
