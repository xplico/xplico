<?php
/*
	Atom and RSS Extractor and Displayer
	(c) 2007-2009  Scriptol.com - Licence Mozilla 1.1.
	commonlib.php
*/

$Common_Content = array();
$Common_Style ="p";
$Common_Date_Font = "size='-1'";

function RSS_Tags($item, $type)
{
	global $Common_Content;

	$y = array();
	$y["title"] = $item->getElementsByTagName("title")->item(0)->firstChild->textContent;
	$y["link"] = $item->getElementsByTagName("link")->item(0)->firstChild->textContent;
	$y["description"] = $item->getElementsByTagName("description")->item(0)->firstChild->textContent;

	$tnl = $item->getElementsByTagName("pubDate");
	if($tnl->length == 0)
	{
		$tnl = $item->getElementsByTagName("lastBuildDate");
	}	
	if($tnl->length != 0)
	{
		$tnl =$tnl->item(0)->firstChild->textContent;	
	}
	else
		$tnl = false;
	
	$y["updated"] = $tnl;	
	$y["type"] = $type;
		
	array_push($Common_Content, $y);		
}


function RSS_Channel($channel)
{
	global $Common_Content;

	$items = $channel->getElementsByTagName("item");
	
	// Processing channel
	
	RSS_Tags($channel, 0);		// get description of channel, type 0
		
	// Processing articles
	
	foreach($items as $item)
	{
		RSS_Tags($item, 1);	// get description of article, type 1
	}
}

function RSS_Retrieve($url)
{
	global $Common_Content;

	$doc  = new DOMDocument();
	$doc->load($url);

	$channels = $doc->getElementsByTagName("channel");
	
	$Common_Content = array();
	
	foreach($channels as $channel)
	{
		RSS_Channel($channel);
	}

	return ( count($Common_Content) > 0);	
}



function Atom_Tags($item)
{
	global $Common_Content;

	$y = array();
	$y["title"] = $item->getElementsByTagName("title")->item(0)->firstChild->textContent;
	$y["link"] = $item->getElementsByTagName("link")->item(0)->getAttribute("href");
	$y["description"] = $item->getElementsByTagName("summary")->item(0)->firstChild->textContent;
	$y["updated"] = $item->getElementsByTagName("updated")->item(0)->firstChild->textContent;	
	$y["type"] = 1;
		
	array_push($Common_Content, $y);		
}

function Atom_Feed($doc)
{
	global $Common_Content;

	$entries = $doc->getElementsByTagName("entry");	

	if($entries->length == 0) return false;

	// Processing feed
	
	$y = array();
	$y["title"] = $doc->getElementsByTagName("title")->item(0)->firstChild->textContent;
	$y["link"] = $doc->getElementsByTagName("link")->item(0)->getAttribute("href");
	$y["description"] = $doc->getElementsByTagName("subtitle")->item(0)->firstChild->textContent;
	$y["updated"] = $doc->getElementsByTagName("updated")->item(0)->firstChild->textContent;
	$y["type"] = 0;

	array_push($Common_Content, $y);

	// Processing articles
	
	foreach($entries as $entry)
	{
		Atom_Tags($entry);		// get description of article, type 1
	}
	
	return true;
}


function Atom_Retrieve($url)
{
	global $Common_Content;

	$doc  = new DOMDocument();
	$doc->load($url);

	$Common_Content = array();
	
	return Atom_Feed($doc);

}



function Common_Display($url, $size = 25, $chanopt = false, $descopt = false, $dateopt = false)
{
	global $Common_Content;
	global $Common_Style;
	global $Common_Date_Font;

	$opened = false;
	$page = "";

	if(Atom_Retrieve($url) === false)
	{
		if(RSS_Retrieve($url) === false)
		{
			return "$url empty...<br />";
		}	
	}	
	if($size > 0)
	{
		$size += 1;	// add one for the channel
		$recents = array_slice($Common_Content, 0, $size);
	}	

	foreach($recents as $article)
	{
		$type = $article["type"];
		
		if($type == 0)
		{
			if($chanopt != true) continue;
			if($opened == true)
			{
				$page .="</ul>\n";
				$opened = false;
			}
			//$page .="<b>";
		}
		else
		{
			if($opened == false && $chanopt == true) 
			{
				$page .= "<ul>\n";
				$opened = true;
			}
		}
		$title = $article["title"];
		$link = $article["link"];
		$page .= "<".$Common_Style."><a href=\"$link\">$title</a>";
		
		if($descopt != false)
		{
			$description = $article["description"];
			if($description != false)
			{
				$page .= "<br>$description";
			}
		}	
		if($dateopt != false)
		{			
			$updated = $article["updated"];
			if($updated != false)
			{
				$page .= "<br /><font $Common_Date_Font>$updated</font>";
			}
		}	
		$page .= "</".$Common_Style.">\n";			
		
		/*
		if($type == 0)
		{
			$page .="<br />";
		}
		*/
	}

	if($opened == true)
	{	
		$page .="</ul>\n";
	}
	return $page."\n";
	
}


?>