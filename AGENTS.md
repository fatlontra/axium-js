Copy-Paste to Agent:

    Role: You are an expert Python reverse-engineer and bot developer specializing in MMORPG automation, memory manipulation (pymem), and A* pathfinding.

    Project Context: We are building a "Hybrid" bot for an isometric 2D game (DarkEden).

        The Network Layer (Node.js): Acts as a local radar. It sniffs TCP packets to maintain a live list of Monster IDs, X/Y coordinates, and HP. It sends this to Python via local sockets/IPC.

        The Logic Layer (Python): This is what you are building. It handles game state, memory reading/writing, map parsing, and pathfinding.

    Core Objectives:
    I need you to scaffold a modular Python project with the following requirements:

    1. Memory Management (pymem)

        Attach to DarkEden.exe.

        Read the player's true Server Coordinates from static base pointers:

            X_COORD_ADDR = "DarkEden.exe" + 0x004A1364

            Y_COORD_ADDR = "DarkEden.exe" + 0x004A1368

        The memory reader must loop continuously to update the bot's current position.

    2. Map & Collision Parsing

        The game uses .map and .mip files to store grid layouts and terrain levels.

        Write a MapParser class that opens a local .map file and converts the binary/hex data into a 2D Python array (grid).

        Walkable tiles should be 0, walls/obstacles should be 1. (Provide a hex-reading scaffolding assuming standard 2D grid byte alignment, and instructions on how we can analyze the headers).

    3. A (A-Star) Pathfinding*

        Implement an optimized A* pathfinding algorithm that ingests the 2D map array.

        It must accept a start_node(x, y) and a target_node(x, y).

        Dynamic Obstacles: The pathfinder must treat incoming monster coordinates (from the Node.js IPC stream) as temporary, non-walkable obstacles on the grid to prevent the bot from getting stuck on mobs.

    4. Movement Execution (Preparation)

        Instead of sending raw network packets (too risky), the bot will initially move by simulating left-clicks on the game window based on calculated next-step coordinates, or by writing to a "Destination X/Y" memory address if we discover it. Set up a placeholder Walker class for this.

    Output Request:
    Please provide the requirements.txt for the necessary libraries, the recommended folder structure, and the Python code for:

        memory_reader.py (pymem setup)

        map_parser.py (handling the .map files)

        pathfinder.py (A* algorithm)