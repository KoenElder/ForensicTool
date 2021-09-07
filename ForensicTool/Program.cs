using System;
using System.IO;
using System.Text;

namespace ForensicTool
{
    class Program
    {

        static void Main(string[] args)
        {
            //if (args.Length == 0)
            //{
            //    Console.WriteLine("This Application Needs A File As A Parameter.");
            //    Console.WriteLine("Please Execute The Program Again From Command Line With The A Parameter.");
            //    Console.ReadLine();
            //    Environment.Exit(0);
            //}
            //string filePath = args[0];
            string filePath = @"C:\Users\elder\Documents\HBO-ICT\jaar 3\Exchange\Modules\Computer Forensics\Sample_1.dd";

            int partitionEntrySize = 16; //for this assignment we will assume that the disk drives are normal MBR's with 16 byte partition entries
            int validPartitions = 4; //standard MBR has 4 partitions
            int directoryEntrySize = 32; //standard FAT directory entry size = 32 bytes
            int sectorSize = 512; //standard FAT sector size = 512 bytes

            for (int PartitionNumber = 0; PartitionNumber < 4; PartitionNumber++)
            {
                string PartitionType = GetValueFromBytes(filePath, (0x1C2 + (PartitionNumber * partitionEntrySize)), 1);

                PartitionType = GetDescriptionFromPartitionType(PartitionType);
                if (PartitionType == "Not-Valid") validPartitions -= 1;

                string PartitionStartingSector = GetValueFromBytes(filePath, (0x1C6 + (PartitionNumber * partitionEntrySize)), 4);
                int PartitionStartingSectorInt = Convert.ToInt32(PartitionStartingSector);

                string PartitionSize = GetValueFromBytes(filePath, (0x1CA + (PartitionNumber * partitionEntrySize)), 4);

                Console.WriteLine("Partition {0}: Type: {1}, Starting Sector: {2}, Size: {3}", PartitionNumber, PartitionType, PartitionStartingSector, PartitionSize);

                if (PartitionNumber == 0)
                {
                    int ByteOffsetPartition1 = PartitionStartingSectorInt * sectorSize;

                    string NumberOfSectorsPerCluster = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x0D), 1);

                    int NumberOfFATCopies = Convert.ToInt32(GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x10), 1));
                    int SizeOfFATCopy = Convert.ToInt32(GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x16), 2));

                    int SizeOfFAT = NumberOfFATCopies * SizeOfFATCopy;

                    int SizeOfReservedArea = Convert.ToInt32(GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x0E), 2));
                    int StartSectorOfRootDirectory = PartitionStartingSectorInt + SizeOfFAT + SizeOfReservedArea;

                    string MaximumNumberOfRootDirectoryEntries = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x11), 2);
                    int RootDirectorySize = (Convert.ToInt32(MaximumNumberOfRootDirectoryEntries) * directoryEntrySize) / sectorSize;

                    int StartingSectorAddressCluster2 = StartSectorOfRootDirectory + RootDirectorySize;

                    Console.WriteLine(" -Number of sectors per cluster: {0}", NumberOfSectorsPerCluster);
                    Console.WriteLine(" -Size of FAT area (in sectors): {0}", SizeOfFAT);
                    Console.WriteLine(" -Size of Root Directory (in sectors): {0}", RootDirectorySize);
                    Console.WriteLine(" -Starting Address of Cluster #2: {0}", StartingSectorAddressCluster2);

                    int ByteOffsetRootDirectory = StartSectorOfRootDirectory * sectorSize;
                    string FileNameFirstByte = GetValueFromBytes(filePath, ByteOffsetRootDirectory, 1);
                    int DeletedFileByteOffset = ByteOffsetRootDirectory;

                    do
                    {
                        FileNameFirstByte = GetValueFromBytes(filePath, (DeletedFileByteOffset += 16), 1);
                    }
                    while (FileNameFirstByte != "E5");

                    string DeletedFileName = GetStringFromHex(filePath, DeletedFileByteOffset, 11);

                    string DeletedFileSize = GetValueFromBytes(filePath, (DeletedFileByteOffset + 0x1C), 4);

                    int DeletedFileStartingCluster = Convert.ToInt32(GetValueFromBytes(filePath, (DeletedFileByteOffset + 0x1A), 2));

                    int DeletedFileClusterStartingAddress = StartingSectorAddressCluster2 + ((DeletedFileStartingCluster - 2) * 8);

                    int DeletedClusterStartingAddressByteOffset = DeletedFileClusterStartingAddress * sectorSize;
                    string DeletedFileFirstCharacters = GetStringFromHex(filePath, DeletedClusterStartingAddressByteOffset, 16);

                    Console.WriteLine(" First Hidden File of this Parition:");
                    Console.WriteLine("     Name: '{0}'", DeletedFileName);
                    Console.WriteLine("     Size(in bytes): {0}", DeletedFileSize);
                    Console.WriteLine("     Cluster Starting Address: {0}", DeletedFileClusterStartingAddress);
                    Console.WriteLine("     First 16 characters of content: '{0}'", DeletedFileFirstCharacters);
                }

                if(PartitionType == "NTFS")
                {
                    int ByteOffsetNTFS = PartitionStartingSectorInt * sectorSize;

                    string NumberOfBytesPerCluster = GetValueFromBytes(filePath, (ByteOffsetNTFS + 0x0B), 2);
                    string NumberOfSectorsPerCluster = GetValueFromBytes(filePath, (ByteOffsetNTFS + 0x0D), 1);
                    int LogicalClusterNumberMFT = Convert.ToInt32(GetValueFromBytes(filePath, (ByteOffsetNTFS + 0x30), 8));

                    int StartingSectorMFT = PartitionStartingSectorInt + (LogicalClusterNumberMFT * 8);
                    int ByteOffsetMFT = StartingSectorMFT * sectorSize;

                    int OffsetFirstAttribute = Convert.ToInt32(GetValueFromBytes(filePath, ByteOffsetMFT + 0x14, 2));
                    string FirstAttributeTypeIdentifier = GetValueFromBytes(filePath, ByteOffsetMFT + OffsetFirstAttribute, 4);
                    FirstAttributeTypeIdentifier = GetDescriptionFromAttributeType(FirstAttributeTypeIdentifier);
                    int FirstAttributeLength = Convert.ToInt32(GetValueFromBytes(filePath, (ByteOffsetMFT + OffsetFirstAttribute + 0x04), 4));

                    int OffsetSecondAttribute = OffsetFirstAttribute + FirstAttributeLength + ByteOffsetMFT;
                    string SecondAttributeTypeIdentifier = GetValueFromBytes(filePath, OffsetSecondAttribute, 4);
                    SecondAttributeTypeIdentifier = GetDescriptionFromAttributeType(SecondAttributeTypeIdentifier);
                    string SecondAttributeLength = GetValueFromBytes(filePath, (OffsetSecondAttribute + 0x04), 4);

                    Console.WriteLine(" -Number of Bytes per Sector: {0}", NumberOfBytesPerCluster);
                    Console.WriteLine(" -Number of Sector per Cluster: {0}", NumberOfSectorsPerCluster);
                    Console.WriteLine(" -Sector Starting Address of MFT file: {0}", StartingSectorMFT);
                    Console.WriteLine("     First Attribute of MFT File: Type: {0}, Length: {1}", FirstAttributeTypeIdentifier, FirstAttributeLength);
                    Console.WriteLine("     Second Attribute of MFT File: Type: {0}, Length: {1}", SecondAttributeTypeIdentifier, SecondAttributeLength);
                }
                Console.WriteLine(); //empty line for readability
            }
            Console.WriteLine(); //empty line for readability
            Console.WriteLine("Total number of valid partitions is: {0}", validPartitions);
            Console.ReadLine();
        }

        static public string GetValueFromBytes(string filePath, long byteOffset, int byteLength)
        {
            using (FileStream rawImageFileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader binaryReader = new BinaryReader(rawImageFileStream))
            {
                rawImageFileStream.Seek(byteOffset, SeekOrigin.Begin);

                if (byteLength == 1)
                {
                    string DecimalValue = binaryReader.ReadByte().ToString("X2");
                    return DecimalValue;
                }
                else
                {
                    byte[] bytes = binaryReader.ReadBytes(byteLength);
                    if (BitConverter.IsLittleEndian)
                    {
                        Array.Reverse(bytes);
                    }
                    string PartitionStartingSectorHexString = BitConverter.ToString(bytes).Replace("-", string.Empty);

                    int DecimalValue = int.Parse(PartitionStartingSectorHexString, System.Globalization.NumberStyles.HexNumber);
                    return DecimalValue.ToString();
                }
            }
        }

        static public string GetStringFromHex(string filePath, long byteOffset, int byteLength) //Text bytes (for file name/content) do not have to be reversed, so we made another method without reversing the byte order
        {
            using (FileStream rawImageFileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            using (BinaryReader binaryReader = new BinaryReader(rawImageFileStream))
            {
                rawImageFileStream.Seek(byteOffset, SeekOrigin.Begin);

                if (byteLength == 1)
                {
                    string DecimalValue = binaryReader.ReadByte().ToString("X2");
                    return DecimalValue;
                }
                else
                {
                    byte[] bytes = binaryReader.ReadBytes(byteLength);

                    string PartitionStartingSectorHexString = BitConverter.ToString(bytes).Replace("-", string.Empty);

                    byte[] raw = new byte[PartitionStartingSectorHexString.Length / 2];
                    for (int i = 0; i < raw.Length; i++)
                    {
                        raw[i] = Convert.ToByte(PartitionStartingSectorHexString.Substring(i * 2, 2), 16);
                    }
                    return Encoding.ASCII.GetString(raw);
                }
            }
        }

        static private string GetDescriptionFromPartitionType(string PartitionType)
        {
            switch (PartitionType)
            {
                case "00":
                    return "Not-Valid";
                case "01":
                    return "12-bit FAT";
                case "02":
                    return "XENIX root";
                case "03":
                    return "XENIX usr";
                case "04":
                    return "16-bit FAT (<32MB)";
                case "05":
                    return "Extended MS-DOS Partition";
                case "06":
                    return "FAT-16 (32MB to 2GB)";
                case "07":
                    return "NTFS";
                case "08":
                    return "Logical sectored FAT12 or FAT-16, OS/2, AIX boot/split";
                case "09":
                    return "AIX data/boot";
                case "0B":
                    return "FAT-32 (CHS)";
                case "0C":
                    return "FAT-32 (LBA)";
                case "0E":
                    return "FAT-16 (LBA)";
                case "83":
                    return "Any native Linux file system";
                case "93":
                    return "Hidden Linux file system";
                case "A8":
                    return "Apple Darwin, Mac OS X UFS";
                case "AF":
                    return "HFS and HFS+";
                default:
                    return "Not Supported In This Forensic Tool";
            }
        }
        static private string GetDescriptionFromAttributeType(string AttributeType)
        {
            switch (AttributeType)
            {
                case "16":
                    return "$STANDARD_INFORMATION";
                case "32":
                    return "$ATTRIBUTE_LIST";
                case "48":
                    return "$FILE_NAME";
                case "64":
                    return "$OBJECT_ID";
                case "80":
                    return "$SECURITY_DESCRIPTOR";
                case "96":
                    return "$VOLUME_NAME";
                case "122":
                    return "$VOLUME_INFORMATION";
                case "128":
                    return "$DATA";
                case "144":
                    return "$INDEX_ROOT";
                case "160":
                    return "$INDEX_ALLOCATION";
                case "176":
                    return "$BITMAP";
                case "192":
                    return "$REPARSE_POINT";
                case "256":
                    return "$LOGGED_UTILITY_STREAM";
                default:
                    return "Not supported in this Forensic Tool";
            }
        }
    }
}