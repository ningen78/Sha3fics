// SHA3-1024 File / Wildcard / Directory Hasher
// Usage:
// dotnet new console -n Sha3Sum1024 -f net8.0
// (replace Program.cs with this file's contents) or add as Program.cs in a new console project
// dotnet add package BouncyCastle.Cryptography
// dotnet build
// dotnet run -- [-r] <file|wildcard|directory>
//
// Behavior:
// - If <file> exists: writes alongside it a "<file>.sha3" file containing: "<filename>\t<sha3-1024>".
// - If <wildcard> (contains * or ?): hashes all matches in its directory and writes to a file named after the pattern with
// * -> [any] and ? -> [x], then ".sha3" (e.g., "logs/*.txt" => "logs/[any].txt.sha3").
// - If <directory>: writes a sibling file "<directory>.sha3" listing all files directly within (or all subfiles with -r).
// - "-r" is only valid with a directory argument; it includes all files in all subdirectories.
//
// Notes:
// - Requires the NuGet package: BouncyCastle.Cryptography (for SHA3-1024)
// - Output lines are sorted by path for determinism. Each line: <relative-filename-to-scope>\t<lowercase-hex 256 chars>
// - Large-file friendly: streaming hash; no file loaded entirely into memory.


using System.Text;
using Org.BouncyCastle.Crypto.Digests; // from BouncyCastle.Cryptography

namespace Sha3fics;

public class Program
{
	static int Main(string[] args)
	{
		if (args.Length == 0)
		{
			PrintUsage();
			return 1;
		}

		var recursive = false;
		string target = null!;

		var queue = new Queue<string>(args);
		while (queue.Count > 0)
		{
			var a = queue.Dequeue();
			if (a is "-r" or "--recursive")
			{
				recursive = true;
			}
			else
			{
				target = a;
				// ignore anything after target for simplicity
				break;
			}
		}

		if (string.IsNullOrWhiteSpace(target))
		{
			Console.Error.WriteLine("error: missing <file|wildcard|directory> argument\n");
			PrintUsage();
			return 1;
		}

		try
		{
			if (File.Exists(target))
			{
				if (recursive)
				{
					Console.Error.WriteLine("warning: -r is ignored when hashing a single file.");
				}

				return HashSingleFile(target);
			}

			if (IsWildcardPattern(target))
			{
				if (recursive)
				{
					Console.Error.WriteLine("warning: -r is ignored when using a wildcard pattern.");
				}

				return HashWildcard(target);
			}

			if (Directory.Exists(target))
			{
				return HashDirectory(target, recursive);
			}

			Console.Error.WriteLine($"error: '{target}' does not exist and is not a wildcard pattern.");
			return 2;
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine("fatal: " + ex.Message);
			return 3;
		}
	}

	static void PrintUsage()
	{
		Console.WriteLine(@"SHA3-1024 hasher
Usage: sha3sum-1024 [-r] <file|wildcard|directory>

Examples:
  sha3sum-1024 README.md
  sha3sum-1024 src/*.cs
  sha3sum-1024 -r ./data
");
	}

	static int HashSingleFile(string filePath)
	{
		var dir = Path.GetDirectoryName(Path.GetFullPath(filePath)) ?? Directory.GetCurrentDirectory();
		var fileNameOnly = Path.GetFileName(filePath);
		var outPath = filePath + ".sha3";

		var entries = new List<(string rel, string hash)>();
		var hash = ComputeSha3_1024_ForFile(filePath);
		entries.Add((fileNameOnly, hash));

		WriteOutput(outPath, entries);
		Console.WriteLine($"1 file hashed -> {outPath}");
		return 0;
	}

	static int HashWildcard(string pattern)
	{
		var full = Path.GetFullPath(ExpandCurrentDirIfBare(pattern));
		var baseDir = Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory();
		var search = Path.GetFileName(full);

		var safeName = MakeSafeWildcardName(search);
		var outPath = Path.Combine(baseDir, safeName + ".sha3");

		string[] files;
		try
		{
			files = Directory.GetFiles(baseDir, search, SearchOption.TopDirectoryOnly);
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"error: unable to evaluate wildcard '{pattern}': {ex.Message}");
			return 2;
		}

		var entries = HashMany(files, baseDir);
		WriteOutput(outPath, entries);
		Console.WriteLine($"{entries.Count} file(s) hashed -> {outPath}");
		return 0;
	}

	static int HashDirectory(string dirPath, bool recursive)
	{
		var fullDir = Path.GetFullPath(dirPath);
		var dirName = Path.GetFileName(Path.TrimEndingDirectorySeparator(fullDir));
		var parent = Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(fullDir)) ??
		             Directory.GetCurrentDirectory();
		var outPath = Path.Combine(parent, dirName + ".sha3");

		var option = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
		string[] files;
		try
		{
			files = Directory.GetFiles(fullDir, "*", option);
		}
		catch (Exception ex)
		{
			Console.Error.WriteLine($"error: unable to enumerate directory '{dirPath}': {ex.Message}");
			return 2;
		}

		var entries = HashMany(files, fullDir);
		WriteOutput(outPath, entries);
		Console.WriteLine($"{entries.Count} file(s) hashed -> {outPath}");
		return 0;
	}

	private static List<(string rel, string hash)> HashMany(IEnumerable<string> files, string baseDir)
	{
		var list = new List<(string rel, string hash)>();
		foreach (var f in files)
		{
			try
			{
				var rel = Path.GetRelativePath(baseDir, f);
				var hash = ComputeSha3_1024_ForFile(f);
				list.Add((rel, hash));
			}
			catch (Exception ex)
			{
				Console.Error.WriteLine($"warn: skipping '{f}': {ex.Message}");
			}
		}

		// stable order
		list.Sort((a, b) => string.CompareOrdinal(a.rel, b.rel));
		return list;
	}

	static void WriteOutput(string outPath, List<(string rel, string hash)> entries)
	{
		using var writer = new StreamWriter(outPath, false, new UTF8Encoding(false));
		foreach (var (rel, hash) in entries)
		{
			writer.Write(rel);
			writer.Write('\t');
			writer.WriteLine(hash);
		}
	}

	static bool IsWildcardPattern(string p)
	{
		return p.IndexOf('*') >= 0 || p.IndexOf('?') >= 0;
	}

	static string ExpandCurrentDirIfBare(string p)
	{
		// If pattern is just like "*.txt" without a directory, anchor to current directory
		if (Path.IsPathRooted(p)) return p;
		if (p.Contains(Path.DirectorySeparatorChar) || p.Contains(Path.AltDirectorySeparatorChar)) return p;
		return Path.Combine(Directory.GetCurrentDirectory(), p);
	}

	static string MakeSafeWildcardName(string search)
	{
		// Replace forbidden wildcard chars with tokens to form a valid filename
		var sb = new StringBuilder(search.Length + 16);
		foreach (var c in search)
		{
			sb.Append(c switch
			{
				'*' => "[any]",
				'?' => "[x]",
				':' => "[colon]", // safety on Windows if someone passed a rooted pattern part
				'|' => "[bar]",
				'"' => "[quote]",
				'<' => "[lt]",
				'>' => "[gt]",
				_ => c
			});
		}

		return sb.ToString();
	}

	static string ComputeSha3_1024_ForFile(string path)
	{
		var digest = new Sha3Digest(1024); // SHA3-1024
		var buffer = new byte[1024 * 1024]; // 1 MiB
		using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, bufferSize: 1024 * 128,
			FileOptions.SequentialScan);
		int read;
		while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
		{
			digest.BlockUpdate(buffer, 0, read);
		}

		var result = new byte[digest.GetDigestSize()];
		digest.DoFinal(result, 0);
		return ToHex(result);
	}

	static string ToHex(byte[] bytes)
	{
		var sb = new StringBuilder(bytes.Length * 2);
		foreach (var b in bytes)
			sb.Append(b.ToString("x2"));
		return sb.ToString();
	}
}