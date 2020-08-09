"use strict";

const logging = true;


const dgram = require("dgram");
const server = dgram.createSocket("udp6");

let fs;
if(logging)
{
	fs = require("fs");
}


const log = async function(message)
{
	if(message.charAt(message.length - 1) !== "\n")
	{
		message = message + "\n";
	}

	const timestamp = (Date.now()/1000).toString(10).padEnd(14, "0") + "    ";

	fs.appendFile("dns.log", timestamp + message, function(){return;});

	return;
}

const sendResponse = function(responseBuffer, transactionIdentifier, clientInfo)
{
	// Write the transaction ID to the response buffer so the client knows how to match it
	responseBuffer.writeUInt16BE(transactionIdentifier, 0);

	server.send(responseBuffer, clientInfo.port, clientInfo.address, function(error)
	{
		if(error)
		{
			log("UDP send error: " + error.toString());
		}
	});

	// Now is a good time to trigger GC if manual GC is configured
	if (global.gc) {global.gc();}
	
	return;
}

const toQueryBuffer = function(name)
{
	if(name.charAt(name.length - 1) === ".")
	{
		name = name.slice(0, -1);
	}

	// Make a list of the lengths of each part
	let lengths = (name.split(".")).map(function(part)
	{
		return part.length;
	});

	// Make a buffer out of the name and add a character to the start.
	let queryBuffer = Buffer.from("." + name);

	// Replace the .s with length fields
	let offset = 0;
	lengths.forEach(function(length, index)
	{
		queryBuffer[offset] = length;
		offset += length + 1;
	});

	return queryBuffer;
}


let records =
[
	{
		"buffer": toQueryBuffer("example.com"),
		"name": "example.com",
		"a": Buffer.from([0x7f, 0x00, 0x00, 0x01]),
		"aaaa": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
	},
	{
		"buffer": toQueryBuffer("ipv6only.test"),
		"name": "ipv6only.test",
		"aaaa": Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])
	},
	{
		"buffer": toQueryBuffer("ipv4only.test"),
		"name": "ipv4only.test",
		"a": Buffer.from([0x7f, 0x00, 0x00, 0x01])
	}
];

for(let index = 0; index < records.length; index++)
{
	//                           TXID         Flags       #Questions  #Answers    #Auth RRs   #Add RRs           
	let baseBuffer = Buffer.from([0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
	//                            0     1     2     3     4     5     6     7     8     9     10    11 

	const hasAdditionalRecords = records[index].hasOwnProperty("a") && records[index].hasOwnProperty("aaaa");
	if(hasAdditionalRecords)
	{
		baseBuffer[11] = 0x01;
	}
	//                                                                 null for name  Type        IN          
	baseBuffer = Buffer.concat([baseBuffer, records[index].buffer, Buffer.from([0x00, 0x00, 0x01, 0x00, 0x01])]);


	// Create answer section variables so we don't have to remake them if there is an A and AAAA for the same record
	let aAnswer;
	let aResponse;
	let aaaaAnswer;
	let aaaaResponse;

	if(records[index].hasOwnProperty("a"))
	{
		//                                    Name ptr    Type A      IN          TTL (300 seconds)       Data length
		aAnswer = Buffer.concat([Buffer.from([0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]), records[index].a]);
		aResponse = Buffer.concat([baseBuffer, aAnswer]);
	}
	
	if(records[index].hasOwnProperty("aaaa"))
	{
		//                                       Name ptr    Type A      IN          TTL (300 seconds)       Data length
		aaaaAnswer = Buffer.concat([Buffer.from([0xC0, 0x0C, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x10]), records[index].aaaa]);
		aaaaResponse = Buffer.concat([baseBuffer, aaaaAnswer]);
	}

	if(hasAdditionalRecords)
	{
		aResponse    = Buffer.concat([   aResponse, aaaaAnswer]);
		aaaaResponse = Buffer.concat([aaaaResponse, aAnswer   ]);
	}


	if(records[index].hasOwnProperty("a"))
	{
		records[index].aResponse = aResponse;
	}

	if(records[index].hasOwnProperty("aaaa"))
	{
		records[index].aaaaResponse = aaaaResponse;
	}
}

server.on("error", function(error)
{
	if(logging)
	{
		log(error.toString());
	}

	return;
});

server.on("message", function(message, clientInfo)
{
	// Check if it is something we don't want to respond to
	if((message.length < 18) || (message.length > 269))
	{
		if(logging)
		{
			log("Long ass message ignored from [" + clientInfo.address + "]:" + clientInfo.port + "\n");
		}

		return;
	}

	if((message[2] !== 0x01) ||
	   (message[3] !== 0x00) ||
	   (message[4] !== 0x00) ||
	   (message[5] !== 0x01))
	{
		// Not a standard query for a single record, ignore

		return;
	}

	if((message[message.length - 4] !== 0x00) ||
	  ((message[message.length - 3] !== 0x01) && (message[message.length - 3] !== 0x1C)) ||
	   (message[message.length - 2] !== 0x00) ||
	   (message[message.length - 1] !== 0x01))
	{
		// Not an IN A or IN AAAA request, ignore

		return;
	}


	let queryType;
	if(message[message.length - 3] === 0x01)
	{
		queryType = "a";
	}
	else
	{
		queryType = "aaaa";
	}

	// Extract the queried name including length but not the null terminator
	const queryBuffer = message.slice(12, message.length - 5);

	// Compare it to all of the record buffers
	let matched = false;
	for(let index = 0; index < records.length; index++)
	{
		// Look for a matching name buffer
		if(queryBuffer.equals(records[index].buffer))
		{
			// But we still need a matching record type to have a true match
			if(records[index].hasOwnProperty(queryType))
			{
				matched = true;
				if(logging)
				{
					log("Received " + queryType + " query for " + records[index].name + " from [" + clientInfo.address + "]:" + (clientInfo.port).toString());
				}

				sendResponse(records[index][queryType + "Response"], message.readUInt16BE(0), clientInfo);
			}
			
			// Either way that's all she wrote
			break;
		}
	}

	return;
});

server.on("listening", function(message)
{
	if(logging)
	{
		log("Listening on [" + server.address().address + "]:" + server.address().port);
	}

	return;
});


server.bind(53);
