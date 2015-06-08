//
//  ViewController.swift
//  HeimdallExample
//
//  Created by Henri Normak on 23/04/15.
//  Copyright (c) 2015 Henri Normak. All rights reserved.
//

import UIKit
import Heimdall

class ViewController: UIViewController, UITextViewDelegate {
    @IBOutlet var textView: UITextView!
    @IBOutlet var bottomConstraint: NSLayoutConstraint!
    var heimdall: Heimdall?
    var text: String = ""
    
    override func viewDidLoad() {
        super.viewDidLoad()
        self.heimdall = Heimdall(tagPrefix: "com.hnormak.heimdall.example", keySize: 1024)
        
        NSNotificationCenter.defaultCenter().addObserver(self, selector: "keyboardWillChange:", name: UIKeyboardWillChangeFrameNotification, object: nil)
    }
    
    deinit {
        NSNotificationCenter.defaultCenter().removeObserver(self)
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    // UITextView delegate
    func textViewDidChange(textView: UITextView) -> Void {        
        self.text = textView.text
    }
    
    // Switching content
    @IBAction func showPlainText() -> Void {
        self.textView.editable = true
        self.textView.text = self.text
    }
    
    @IBAction func showDecryptedText() -> Void {
        self.textView.editable = false
        if let encrypted = heimdall?.encrypt(self.text), decrypted = heimdall?.decrypt(encrypted) {
            self.textView.text = decrypted
        }
    }
    
    @IBAction func showEncryptedText() -> Void {
        self.textView.editable = false
        if let encrypted = heimdall?.encrypt(self.text) {
            self.textView.text = encrypted
        }
    }
    
    @IBAction func showEncryptedSignature() -> Void {
        self.textView.editable = false
        if let signature = heimdall?.sign(self.text) {
            self.textView.text = signature
        }
    }
    
    // Keyboard insetting
    func keyboardWillChange(notification: NSNotification) {
        if let userInfo = notification.userInfo, value = userInfo[UIKeyboardFrameEndUserInfoKey] as? NSValue, duration = userInfo[UIKeyboardAnimationDurationUserInfoKey] as? Double, curve = userInfo[UIKeyboardAnimationCurveUserInfoKey] as? UInt {
        
            let frame = value.CGRectValue()
            let intersection = CGRectIntersection(frame, self.view.frame)
            
            self.view.setNeedsLayout()
            self.bottomConstraint.constant = CGRectGetHeight(intersection)
        
            UIView.animateWithDuration(duration, delay: 0.0, options: UIViewAnimationOptions(rawValue: curve), animations: { _ in
                    self.view.setNeedsLayout()
                }, completion: nil)
        }
    }
}
