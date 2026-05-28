"""
Test DumpIt Subprocess Configuration
=====================================
Test different ways to call DumpIt from Python
"""

import subprocess
import sys
from pathlib import Path
import time


def test_method_1_with_stdin():
    """Method 1: Popen with stdin to send 'y'"""
    print("\n" + "=" * 70)
    print("Test 1: Popen with stdin input")
    print("=" * 70)
    
    dumpit = Path("tools/DumpIt.exe")
    output_dir = Path("test_output_1")
    output_dir.mkdir(exist_ok=True)
    
    try:
        proc = subprocess.Popen(
            [str(dumpit), '/O', str(output_dir)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Send 'y' to accept prompt
        print("Sending 'y' to DumpIt...")
        proc.stdin.write('y\n')
        proc.stdin.flush()
        
        # Wait a bit
        time.sleep(2)
        
        # Check if process is still running
        if proc.poll() is None:
            print("✅ DumpIt is running!")
            print("⏳ Waiting for completion (max 60s)...")
            
            try:
                stdout, stderr = proc.communicate(timeout=60)
                
                if proc.returncode == 0:
                    print("✅ SUCCESS! DumpIt completed")
                    
                    # Check for output file
                    files = list(output_dir.glob("*.dmp"))
                    if files:
                        print(f"   Created: {files[0].name}")
                        print(f"   Size: {files[0].stat().st_size / (1024*1024):.1f} MB")
                        return True
                else:
                    print(f"❌ Failed with code {proc.returncode}")
                    print(f"Output: {stdout[:200]}")
                    
            except subprocess.TimeoutExpired:
                print("⚠️  Still running after 60s (probably working)")
                proc.kill()
                return None
        else:
            print(f"❌ Process exited immediately with code {proc.returncode}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_method_2_no_stdin():
    """Method 2: Try without stdin (hope /Q works)"""
    print("\n" + "=" * 70)
    print("Test 2: Without stdin (relying on /Q)")
    print("=" * 70)
    
    dumpit = Path("tools/DumpIt.exe")
    output_dir = Path("test_output_2")
    output_dir.mkdir(exist_ok=True)
    
    try:
        proc = subprocess.Popen(
            [str(dumpit), '/Q', '/O', str(output_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("⏳ Waiting for DumpIt...")
        time.sleep(2)
        
        if proc.poll() is None:
            print("✅ DumpIt is running!")
            try:
                stdout, stderr = proc.communicate(timeout=60)
                
                if proc.returncode == 0:
                    print("✅ SUCCESS!")
                    files = list(output_dir.glob("*.dmp"))
                    if files:
                        print(f"   Created: {files[0].name}")
                        return True
                else:
                    print(f"❌ Failed: {proc.returncode}")
                    
            except subprocess.TimeoutExpired:
                print("⚠️  Still running (probably working)")
                proc.kill()
                return None
        else:
            print(f"❌ Exited with code {proc.returncode}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_method_3_shell():
    """Method 3: Use shell=True"""
    print("\n" + "=" * 70)
    print("Test 3: Using shell=True")
    print("=" * 70)
    
    dumpit = Path("tools/DumpIt.exe")
    output_dir = Path("test_output_3")
    output_dir.mkdir(exist_ok=True)
    
    try:
        # Build command string
        cmd = f'echo y | "{dumpit}" /O "{output_dir}"'
        print(f"Command: {cmd}")
        
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        print("⏳ Waiting for DumpIt...")
        time.sleep(2)
        
        if proc.poll() is None:
            print("✅ DumpIt is running!")
            try:
                stdout, stderr = proc.communicate(timeout=60)
                
                if proc.returncode == 0:
                    print("✅ SUCCESS!")
                    files = list(output_dir.glob("*.dmp"))
                    if files:
                        print(f"   Created: {files[0].name}")
                        return True
                else:
                    print(f"❌ Failed: {proc.returncode}")
                    
            except subprocess.TimeoutExpired:
                print("⚠️  Still running")
                proc.kill()
                return None
        else:
            print(f"❌ Exited with code {proc.returncode}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def test_method_4_input_file():
    """Method 4: Create input file with 'y'"""
    print("\n" + "=" * 70)
    print("Test 4: Using input redirection")
    print("=" * 70)
    
    dumpit = Path("tools/DumpIt.exe")
    output_dir = Path("test_output_4")
    output_dir.mkdir(exist_ok=True)
    
    # Create input file
    input_file = Path("dumpit_input.txt")
    input_file.write_text("y\n")
    
    try:
        with open(input_file) as f:
            proc = subprocess.Popen(
                [str(dumpit), '/O', str(output_dir)],
                stdin=f,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
        print("⏳ Waiting for DumpIt...")
        time.sleep(2)
        
        if proc.poll() is None:
            print("✅ DumpIt is running!")
            try:
                stdout, stderr = proc.communicate(timeout=60)
                
                if proc.returncode == 0:
                    print("✅ SUCCESS!")
                    files = list(output_dir.glob("*.dmp"))
                    if files:
                        print(f"   Created: {files[0].name}")
                        return True
                else:
                    print(f"❌ Failed: {proc.returncode}")
                    
            except subprocess.TimeoutExpired:
                print("⚠️  Still running")
                proc.kill()
                return None
        else:
            print(f"❌ Exited with code {proc.returncode}")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        return False
    finally:
        if input_file.exists():
            input_file.unlink()


def main():
    print("\n" + "=" * 70)
    print("DumpIt Subprocess Testing Suite")
    print("=" * 70)
    print("\nTesting different methods to call DumpIt from Python...")
    print("This will help us find the best approach for your system.")
    
    # Check if DumpIt exists
    dumpit = Path("tools/DumpIt.exe")
    if not dumpit.exists():
        print(f"\n❌ DumpIt not found at: {dumpit}")
        print("   Please place DumpIt.exe in tools/ directory")
        return
    
    print(f"\n✅ Found DumpIt at: {dumpit}")
    print("\nNote: Each test creates a small dump. You can delete test_output_* folders after.")
    
    input("\nPress Enter to start testing...")
    
    results = {}
    
    # Test all methods
    results['Method 1 (stdin)'] = test_method_1_with_stdin()
    results['Method 2 (/Q flag)'] = test_method_2_no_stdin()
    results['Method 3 (shell)'] = test_method_3_shell()
    results['Method 4 (input file)'] = test_method_4_input_file()
    
    # Summary
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    
    for method, result in results.items():
        if result is True:
            print(f"✅ {method}: SUCCESS")
        elif result is None:
            print(f"⚠️  {method}: STILL RUNNING (probably works)")
        else:
            print(f"❌ {method}: FAILED")
    
    # Recommendation
    print("\n" + "=" * 70)
    print("RECOMMENDATION")
    print("=" * 70)
    
    successful = [m for m, r in results.items() if r is True]
    
    if successful:
        print(f"\n✅ Use: {successful[0]}")
        print("   This method successfully completed a RAM acquisition!")
    else:
        still_running = [m for m, r in results.items() if r is None]
        if still_running:
            print(f"\n⚠️  {still_running[0]} is likely working but took >60s")
            print("   RAM acquisition is slow - this is normal")
            print("   Check test_output_* folders for .dmp files")
        else:
            print("\n❌ No method worked automatically")
            print("   Recommendation: Run DumpIt manually, then use:")
            print("   python main.py --analyze <dump_file>")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing cancelled")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()