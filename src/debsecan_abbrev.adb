pragma License (GPL);
------------------------------------------------------------------------------
-- EMAIL: <darkestkhan@gmail.com>                                           --
-- License: GNU GPLv3 or any later as published by Free Software Foundation --
-- (see README file)                                                        --
--                    Copyright © 2013 darkestkhan                          --
------------------------------------------------------------------------------
--  This Program is Free Software: You can redistribute it and/or modify    --
--  it under the terms of The GNU General Public License as published by    --
--    the Free Software Foundation, either version 3 of the license, or     --
--                (at Your option) any later version.                       --
--                                                                          --
--      This Program is distributed in the hope that it will be useful,     --
--      but WITHOUT ANY WARRANTY; without even the implied warranty of      --
--      MERCHANTABILITY or FITNESS for A PARTICULAR PURPOSE. See the        --
--              GNU General Public License for more details.                --
--                                                                          --
--    You should have received a copy of the GNU General Public License     --
--   along with this program. If not, see <http://www.gnu.org/licenses/>.   --
------------------------------------------------------------------------------

  ----------------------------------------------------------------------------
  -- Here be Dragons: This is quick and dirty hack for counting number of   --
  -- security issues affecting installed packages (as reported by debsecan. --
  -- NOTE: It is totally unoptimized and as accurate as Ada.Strings.Hash    --
  -- function's output is distributed.                                      --
  ----------------------------------------------------------------------------

with Interfaces.C;
with Ada.Text_IO;
with Ada.Unchecked_Deallocation;
with Ada.Containers;
with Ada.Containers.Vectors;
with Ada.Directories;
with Ada.Strings.Hash;
with Ada.Strings.Fixed;
use type Ada.Containers.Hash_Type;

with XDG;

procedure debsecan_Abbrev is

  ----------------------------------------------------------------------------
  -- Thick binding to System call.
  procedure System (Command: in String)
  is
    use type Interfaces.C.int;

    function System (Command: in Interfaces.C.Char_Array)
      return Interfaces.C.int;
    pragma Import (StdCall, System, "system");
    Result: constant Interfaces.C.int := System (Interfaces.C.To_C (Command));
  begin
    if Result = -1 then
      Ada.Text_IO.Put_Line ("debsecan not present in your $PATH.");
      Ada.Text_IO.Put_Line
        ("Are you sure that debsecan is installed on your system?");
      raise Program_Error;
    elsif Result > 0 then
      Ada.Text_IO.Put_Line ("Some error occurred while executing debsecab.");
      Ada.Text_IO.Put_Line ("Aborting further execution of program.");
      raise Program_Error;
    end if;
  end System;

  type String_Access is access String;
  procedure Free is new Ada.Unchecked_Deallocation (String, String_Access);

  type Package_Security_Info is
  record
    Package_Name  : String_Access := Null;
    Hash_Of_Name  : Ada.Containers.Hash_Type;
    Security      : Natural := 0;
  end record;

  ----------------------------------------------------------------------------
  -- Return directory for cache data used by debsecan_abbrev.
  function Cache_Home return String
  is
    Tmp: constant String := XDG.Cache_Home;
    Dir: constant String := "debsecan_abbrev/";
  begin
    if Tmp (Tmp'Last .. Tmp'Last) = "/" then
      return Tmp & Dir;
    else
      return Tmp & '/' & Dir;
    end if;
  end Cache_Home;

  ----------------------------------------------------------------------------
  -- Check if Cache_Home exists and if it is directory. If it doesn't exist
  -- create path to Cache_Home. If it isn't directory raise Program_Error.
  procedure Create_Cache_Home
  is
    package AD renames Ada.Directories;
    use type AD.File_Kind;
  begin
    if AD.Exists (Cache_Home) then
      if AD.Kind (Cache_Home) /= AD.Directory then
        raise Program_Error with  "Fatal Error: " & Cache_Home &
                                  " exists but isn't directory";
      end if;
    else
      AD.Create_Path (Cache_Home);
    end if;
  end Create_Cache_Home;

  ----------------------------------------------------------------------------
  -- Check if two Package_Security_Info are describing the same package.
  -- NOTE that this doesn't check if two records are identical.
  function "=" (Left, Right: in Package_Security_Info) return Boolean
  is
  begin
    return Left.Hash_Of_Name = Right.Hash_Of_Name;
  end "=";

  ----------------------------------------------------------------------------
  -- Check which of the two Package_Security_Info records has less security
  -- issues.
  -- NOTE that this function is declared only for the purpose of sorting generic
  -- in Ada.Containers.Vectors.
  function "<" (Left, Right: Package_Security_Info) return Boolean
  is
  begin
    return Left.Security < Right.Security;
  end "<";

  package Package_Security_Info_Vectors is
    new Ada.Containers.Vectors (Positive, Package_Security_Info);

  package Package_Security_Info_Vectors_Sort is new
    Package_Security_Info_Vectors.Generic_Sorting;

  ----------------------------------------------------------------------------
  -- Print entire vector on screen.
  procedure Put_Package_Security_Info_Vector
    (This: in Package_Security_Info_Vectors.Vector)
  is
    package PSIV renames Package_Security_Info_Vectors;
    package TIO renames Ada.Text_IO;

    procedure Put_PSI (Position: PSIV.Cursor)
    is
      Element: Package_Security_Info := PSIV.Element (Position);
    begin
      TIO.Put_Line
        (Natural'Image (Element.Security) & " " & Element.Package_Name.all);
      Free (Element.Package_Name);
    end Put_PSI;

  begin
    PSIV.Iterate (This, Put_PSI'Access);
  end Put_Package_Security_Info_Vector;

  ----------------------------------------------------------------------------
  -- Parse summary file.
  function Parse_Summary return Package_Security_Info_Vectors.Vector
  is
    -- Line format of debsecan is:
    -- <vulnerability_ID><space><package_name>[<space><severity>]

    Parse_Error: exception;

    package TIO renames Ada.Text_IO;
    package Fixed renames Ada.Strings.Fixed;
    use type Package_Security_Info_Vectors.Vector;
    FD: TIO.File_Type;
    Result: Package_Security_Info_Vectors.Vector :=
      Package_Security_Info_Vectors.Empty_Vector;

    procedure Increment (Element: in out Package_Security_Info)
    is
    begin
      Element.Security := Element.Security + 1;
    end Increment;

    -- Return position of first space in line.
    function Pos_Of_First_Space (Item: in String) return Natural
    is
    begin
      for I in Item'Range loop
        if Item (I) = ' ' then
          return I;
        end if;
      end loop;
      raise Parse_Error;
    end Pos_Of_First_Space;

  begin
    TIO.Open (FD, TIO.In_File, Cache_Home & "summary");

    Parse:
    while not TIO.End_Of_File (FD) loop
      declare
        package PSIV renames Package_Security_Info_Vectors;
        Line: constant String := TIO.Get_Line (FD);
        Element: Package_Security_Info;
        Start_Of_Package_Name: constant Natural := Pos_Of_First_Space (Line) + 1;
        End_Of_Package_Name  : constant Natural :=
          Fixed.Index (Line, " ", Start_Of_Package_Name );
      begin
        if End_Of_Package_Name = 0 then
          Element.Hash_Of_Name :=
            Ada.Strings.Hash
              ( Line (Start_Of_Package_Name .. Line'Last)
              );
        else
          Element.Hash_Of_Name :=
            Ada.Strings.Hash
              ( Line (Start_Of_Package_Name .. End_Of_Package_Name)
              );
        end if;

        if PSIV.Contains (Result, Element) then
          PSIV.Update_Element
            (Result, PSIV.Find (Result, Element), Increment'Access);
        else
          if End_Of_Package_Name = 0 then
            Element.Package_Name :=
              new String'(Line (Start_Of_Package_Name .. Line'Last));
          else
            Element.Package_Name :=
              new String'(Line (Start_Of_Package_Name .. End_Of_Package_Name));
          end if;
          Element.Security := 1;
          Result := Result & Element;
        end if;
      end;
    end loop Parse;

    TIO.Close (FD);
    return Result;
  end Parse_Summary;

  ----------------------------------------------------------------------------
  -- Compute total number of CVEs.
  function Total (Item: in Package_Security_Info_Vectors.Vector)
    return Package_Security_Info
  is
    package PSIV renames Package_Security_Info_Vectors;

    Total_CVEs: Package_Security_Info;

    procedure Total_Aux (Position: in PSIV.Cursor)
    is
    begin
      Total_CVEs.Security :=
        Total_CVEs.Security + PSIV.Element (Position).Security;
    end Total_Aux;

  begin
    PSIV.Iterate (Item, Total_Aux'Access);
    Total_CVEs.Package_Name := new String'("Total");
    Total_CVEs.Hash_Of_Name := Ada.Strings.Hash (Total_CVEs.Package_Name.all);
    return Total_CVEs;
  end Total;

  ----------------------------------------------------------------------------

  use type Package_Security_Info_Vectors.Vector;
  Parsed_Summary: Package_Security_Info_Vectors.Vector;

begin
  Create_Cache_Home;
  System ("debsecan >" & Cache_Home & "summary");
  Parsed_Summary := Parse_Summary;
  Package_Security_Info_Vectors_Sort.Sort (Parsed_Summary);
  Parsed_Summary := Parsed_Summary & Total (Parsed_Summary);
  Put_Package_Security_Info_Vector (Parsed_Summary);
end debsecan_Abbrev;
