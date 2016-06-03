/* A simple jQuery-based Table of Contents generator
 * I needed a table of contents for some static markdown pages I created
 * with bluecloth and rails (I'll make this a gem yet) and this is the result.
 *
 * This is one of my first afternoon forays into jQuery so it probably isn't
 * the greatest code I've ever written. I have fully annotated the code with
 * comments for others to learn and understand. Remove them before use.
 *
 * Requires jQuery
 */

// You want to start processing the page after it loads
window.onload = function () {
  // Looks for an element with the class "toc" and appends an empty list
  $(".toc").append("<ol id='toc'></ul>")
  // find the new list
  var TOC = $("ol#toc");

  // loop over every h2 element on the page
  // jQuery allows you to use the multiple selector (replace $('h2')
  // with $('h2,h3')) if you want to loop muliple headings instead.
  $.each($('h2'), function(k, v) {
    var heading = $(v); // get the heading
    var headingText = $(v).text(); // get the value of the heading
    // make a URI-friendly id for the heading
    var headingID = headingText.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    $(v).attr("id", headingID); //assign the new id
    // change the heading text to include a number for prettier headings
    heading.text((k+1) +". " + headingText);
    // create a link in the list for the heading
    TOC.append("<li><a href=\"#" + headingID +"\">" + headingText + "</a></li>" );
  });
  // Put a title on the table of contents
  $(".toc").prepend("<h2>Table of Contents</h2>")
}
/* Copyright (c) 2012 Chris Curran

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/