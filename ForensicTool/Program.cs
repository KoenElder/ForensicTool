using System;
using System.IO;

namespace ForensicTool
{
    class Program
    {

        static void Main(string[] args)
        {
            //if(args.Length == 0)
            //{
            // Console.WriteLine("This Application Needs A File As A Parameter.");
            // Console.WriteLine("Please Execute The Program Again From Command Line With The A Parameter.");
            // Console.ReadLine();
            // Environment.Exit(0);
            //} 
            //string filePath = args[0];
            string filePath = @"C:\Users\Marle\OneDrive\Documenten\test\Sample_1.dd";

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

                string PartitionSize = GetValueFromBytes(filePath, (0x1CA + (PartitionNumber * partitionEntrySize)), 4);

                Console.WriteLine("Partition {0}: Type: {1} Starting Sector: {2} Size: {3}", PartitionNumber, PartitionType, PartitionStartingSector, PartitionSize);

                if (PartitionNumber == 0)
                {
                    //phase 2B
                    // ga naar byteOffset PartitionStartingSector
                    int PartitionStartingSectorInt = Convert.ToInt32(PartitionStartingSector);
                    int ByteOffsetPartition1 = Convert.ToInt32(PartitionStartingSector) * 512;

                    string NumberOfSectorsPerCluster = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x0D), 1);

                    string NumberOfFATCopies = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x10), 1);
                    string SizeOfFATCopy = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x16), 2);

                    int SizeOfFAT = Convert.ToInt32(NumberOfFATCopies) * Convert.ToInt32(SizeOfFATCopy);

                    string SizeOfReservedArea = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x0E), 2);
                    string StartSectorOfRootDirectory = (PartitionStartingSectorInt + SizeOfFAT + Convert.ToInt32(SizeOfReservedArea)).ToString();

                    string MaximumNumberOfRootDirectoryEntries = GetValueFromBytes(filePath, (ByteOffsetPartition1 + 0x11), 2);
                    string RootDirectorySize = ((Convert.ToInt32(MaximumNumberOfRootDirectoryEntries) * directoryEntrySize) / sectorSize).ToString();

                    string StartingSectorAddressCluster2 = (Convert.ToInt32(StartSectorOfRootDirectory) + Convert.ToInt32(RootDirectorySize)).ToString();

                    Console.WriteLine(" -Number of sectors per cluster: {0}", NumberOfSectorsPerCluster);
                    Console.WriteLine(" -Size of FAT area (in sectors): {0}", SizeOfFAT);
                    Console.WriteLine(" -Size of Root Directory (in sectors): {0}", RootDirectorySize);
                    Console.WriteLine(" -Starting Address of Cluster #2: {0}", StartingSectorAddressCluster2);
                }
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
    }
}